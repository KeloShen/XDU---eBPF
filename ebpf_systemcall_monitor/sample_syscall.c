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
struct syscallcntkey {
  u8 cid[CONTAINER_ID_LEN];
  u32 pid;
  u8 comm[TASK_COMM_LEN];
  u32 syscall_id;
};
const struct syscallcntkey *unused__ __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct syscallcntkey);
  __type(value, u64);
  __uint(max_entries, 1024);
} syscall_cnt SEC(".maps");
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
/*--------tools end-----------*/

/*--------ebpf programs-----------*/
SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long syscall_id) {
  struct task_struct *curr_task = (struct task_struct *)bpf_get_current_task();
  if (get_task_level_core(curr_task) == 0) {
    // level 0 means the task is in the root pid namespace
    return 0;
  }

  struct syscallcntkey key = {
      .syscall_id = syscall_id,
      .pid = bpf_get_current_pid_tgid() >> 32,
  };
  bpf_get_current_comm(key.comm, sizeof(key.comm));
  get_cid_core((struct task_struct *)bpf_get_current_task(), &key.cid);
  u64 *sys_cnt = bpf_map_lookup_elem(&syscall_cnt, &key);
  if (sys_cnt) {
    *sys_cnt += 1;
  } else {
    u64 one = 1;
    bpf_map_update_elem(&syscall_cnt, &key, &one, BPF_ANY);
  }
  
  // TODO: add your code here
  
  return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(sys_exit, struct pt_regs *regs, long ret) {
  struct task_struct *curr_task = (struct task_struct *)bpf_get_current_task();
  if (get_task_level_core(curr_task) == 0) {
    // level 0 means the task is in the root pid namespace
    return 0;
  }
  // for x86
  uint32_t syscall_id = (uint32_t)regs->orig_ax;

  // TODO: add your code here

  return 0;
}
/*--------ebpf programs end-----------*/

char LICENSE[] SEC("license") = "GPL";