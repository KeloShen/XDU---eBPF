#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/*--------define-----------*/
#define CONTAINER_ID_LEN 32
#define CONTAINER_ID_USE_LEN 12

#define INFO_LEN 64

#define AF_INET 2
#define AF_INET6 10

#define FILEPATH_LEN 128
#define FILE_MAXDEPTH 32
#define FSNAME_LEN 64
/*--------define end-----------*/

/*--------data structs-----------*/
struct fileopen_event {
  u64 timestamp;
  u32 pid;
  u8 comm[TASK_COMM_LEN];
  u8 filename[FILE_MAXDEPTH][FILEPATH_LEN];
  u8 fsname[FSNAME_LEN];
  u8 cid[CONTAINER_ID_LEN];
};
const struct fileopen_event *unused_ __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 10);
} fileopen_rb SEC(".maps");
/*--------data structs end-----------*/

/*--------tools-----------*/
static int get_cid_core(struct task_struct *task, u8 *cid) {
  struct css_set *css = BPF_CORE_READ(task, cgroups);
  struct cgroup_subsys_state *sbs = BPF_CORE_READ(css, subsys[0]);
  struct cgroup *cg = BPF_CORE_READ(sbs, cgroup);
  struct kernfs_node *knode = BPF_CORE_READ(cg, kn);
  struct kernfs_node *pknode = BPF_CORE_READ(knode, parent);
  u8 tmp_cid[CONTAINER_ID_LEN];
  u8 *_cid;
  if (pknode != NULL) {
    u8 *aus = (u8 *)BPF_CORE_READ(knode, name);
    bpf_core_read_str(&tmp_cid, CONTAINER_ID_LEN, aus);
    if (tmp_cid[6] == '-')
      _cid = &tmp_cid[7];
    else
      _cid = (u8 *)&tmp_cid;
    bpf_core_read_str(cid, CONTAINER_ID_USE_LEN, _cid);
  }
  return sizeof(cid);
}

static int get_task_level_core(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
}

// 添加文件名前的斜杠
static int add_head_slash(char *str) {
  if (str[0] == '/' && str[1] == 0) {
    char empty_str[FILEPATH_LEN] = "";
    bpf_probe_read_kernel_str(str, FILEPATH_LEN, empty_str);
    return -1;
  }
  char tmp[FILEPATH_LEN];
  bpf_probe_read_kernel_str(tmp, FILEPATH_LEN, str);
  char *_str = &str[1];
  bpf_probe_read_kernel_str(_str, FILEPATH_LEN - 1, tmp);
  str[0] = '/';
  return 1;
}

// 添加文件名前的斜杠
static void get_dentry_name_core(struct dentry *den, char *name) {
  u8 *namep = (u8 *)BPF_CORE_READ(den, d_name.name);
  bpf_core_read_str(name, FILEPATH_LEN, namep);
  add_head_slash(name);
}


/*--------tools end-----------*/


// https://elixir.bootlin.com/linux/v6.5/source/fs/namei.c#L3812
SEC("kretprobe/do_filp_open")
int BPF_KRETPROBE(kretprobe_do_filp_open, struct file *filp) {
  struct task_struct *cur_task = (struct task_struct *)bpf_get_current_task();
  if (get_task_level_core(cur_task) == 0) {
    return 0;
  }
  struct fileopen_event *event =
      bpf_ringbuf_reserve(&fileopen_rb, sizeof(struct fileopen_event), 0);
  if (!event) {
    return 0;
  }
  event->timestamp = bpf_ktime_get_ns();
  event->pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(event->comm, sizeof(event->comm));
  get_cid_core(cur_task, event->cid);
  struct file *fi = filp;

  // todo: add your code here

  if (event->filename[0][0] == 0) {
    bpf_ringbuf_discard(event, 0);
  } else {
    bpf_ringbuf_submit(event, 0);
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";