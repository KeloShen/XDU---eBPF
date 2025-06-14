#!/usr/bin/env python3
from bcc import BPF
import time
import ctypes
import sys
from collections import defaultdict
import os

# 系统调用名称映射
syscall_names = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    25: "mremap",
    26: "msync",
    27: "mincore",
    28: "madvise",
    29: "shmget",
    30: "shmat",
    31: "shmctl",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    36: "getitimer",
    37: "alarm",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    64: "semget",
    65: "semop",
    66: "semctl",
    67: "shmdt",
    68: "msgget",
    69: "msgsnd",
    70: "msgrcv",
    71: "msgctl",
    72: "fcntl",
    73: "flock",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    94: "lchown",
    95: "umask",
    96: "gettimeofday",
    97: "getrlimit",
    98: "getrusage",
    99: "sysinfo",
    100: "times",
    101: "ptrace",
    102: "getuid",
    103: "syslog",
    104: "getgid",
    105: "setuid",
    106: "setgid",
    107: "geteuid",
    108: "getegid",
    109: "setpgid",
    110: "getppid",
    111: "getpgrp",
    112: "setsid",
    113: "setreuid",
    114: "setregid",
    115: "getgroups",
    116: "setgroups",
    117: "setresuid",
    118: "getresuid",
    119: "setresgid",
    120: "getresgid",
    121: "getpgid",
    122: "setfsuid",
    123: "setfsgid",
    124: "getsid",
    125: "capget",
    126: "capset",
    127: "rt_sigpending",
    128: "rt_sigtimedwait",
    129: "rt_sigqueueinfo",
    130: "rt_sigsuspend",
    131: "sigaltstack",
    132: "utime",
    133: "mknod",
    134: "uselib",
    135: "personality",
    136: "ustat",
    137: "statfs",
    138: "fstatfs",
    139: "sysfs",
    140: "getpriority",
    141: "setpriority",
    142: "sched_setparam",
    143: "sched_getparam",
    144: "sched_setscheduler",
    145: "sched_getscheduler",
    146: "sched_get_priority_max",
    147: "sched_get_priority_min",
    148: "sched_rr_get_interval",
    149: "mlock",
    150: "munlock",
    151: "mlockall",
    152: "munlockall",
    153: "vhangup",
    154: "modify_ldt",
    155: "pivot_root",
    156: "sysctl",
    157: "prctl",
    158: "arch_prctl",
    159: "adjtimex",
    160: "setrlimit",
    161: "chroot",
    162: "sync",
    163: "acct",
    164: "settimeofday",
    165: "mount",
    166: "umount2",
    167: "swapon",
    168: "swapoff",
    169: "reboot",
    170: "sethostname",
    171: "setdomainname",
    172: "iopl",
    173: "ioperm",
    174: "create_module",
    175: "init_module",
    176: "delete_module",
    177: "get_kernel_syms",
    178: "query_module",
    179: "quotactl",
    180: "nfsservctl",
    181: "getpmsg",
    182: "putpmsg",
    183: "afs_syscall",
    184: "tuxcall",
    185: "security",
    186: "gettid",
    187: "readahead",
    188: "setxattr",
    189: "lsetxattr",
    190: "fsetxattr",
    191: "getxattr",
    192: "lgetxattr",
    193: "fgetxattr",
    194: "listxattr",
    195: "llistxattr",
    196: "flistxattr",
    197: "removexattr",
    198: "lremovexattr",
    199: "fremovexattr",
    200: "tkill",
    201: "time",
    202: "futex",
    203: "sched_setaffinity",
    204: "sched_getaffinity",
    205: "set_thread_area",
    206: "io_setup",
    207: "io_destroy",
    208: "io_getevents",
    209: "io_submit",
    210: "io_cancel",
    211: "get_thread_area",
    212: "lookup_dcookie",
    213: "epoll_create",
    214: "epoll_ctl_old",
    215: "epoll_wait_old",
    216: "remap_file_pages",
    217: "getdents64",
    218: "set_tid_address",
    219: "restart_syscall",
    220: "semtimedop",
    221: "fadvise64",
    222: "timer_create",
    223: "timer_settime",
    224: "timer_gettime",
    225: "timer_getoverrun",
    226: "timer_delete",
    227: "clock_settime",
    228: "clock_gettime",
    229: "clock_getres",
    230: "clock_nanosleep",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    234: "tgkill",
    235: "utimes",
    236: "vserver",
    237: "mbind",
    238: "set_mempolicy",
    239: "get_mempolicy",
    240: "mq_open",
    241: "mq_unlink",
    242: "mq_timedsend",
    243: "mq_timedreceive",
    244: "mq_notify",
    245: "mq_getsetattr",
    246: "kexec_load",
    247: "waitid",
    248: "add_key",
    249: "request_key",
    250: "keyctl",
    251: "ioprio_set",
    252: "ioprio_get",
    253: "inotify_init",
    254: "inotify_add_watch",
    255: "inotify_rm_watch",
    256: "migrate_pages",
    257: "openat",
    258: "mkdirat",
    259: "mknodat",
    260: "fchownat",
    261: "futimesat",
    262: "newfstatat",
    263: "unlinkat",
    264: "renameat",
    265: "linkat",
    266: "symlinkat",
    267: "readlinkat",
    268: "fchmodat",
    269: "faccessat",
    270: "pselect6",
    271: "ppoll",
    272: "unshare",
    273: "set_robust_list",
    274: "get_robust_list",
    275: "splice",
    276: "tee",
    277: "sync_file_range",
    278: "vmsplice",
    279: "move_pages",
    280: "utimensat",
    281: "epoll_pwait",
    282: "signalfd",
    283: "timerfd_create",
    284: "eventfd",
    285: "fallocate",
    286: "timerfd_settime",
    287: "timerfd_gettime",
    288: "accept4",
    289: "signalfd4",
    290: "eventfd2",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    294: "inotify_init1",
    295: "preadv",
    296: "pwritev",
    297: "rt_tgsigqueueinfo",
    298: "perf_event_open",
    299: "recvmmsg",
    300: "fanotify_init",
    301: "fanotify_mark",
    302: "prlimit64",
    303: "name_to_handle_at",
    304: "open_by_handle_at",
    305: "clock_adjtime",
    306: "syncfs",
    307: "sendmmsg",
    308: "setns",
    309: "getcpu",
    310: "process_vm_readv",
    311: "process_vm_writev",
    312: "kcmp",
    313: "finit_module",
    314: "sched_setattr",
    315: "sched_getattr",
    316: "renameat2",
    317: "seccomp",
    318: "getrandom",
    319: "memfd_create",
    320: "kexec_file_load",
    321: "bpf",
    322: "execveat",
    323: "userfaultfd",
    324: "membarrier",
    325: "mlock2",
    326: "copy_file_range",
    327: "preadv2",
    328: "pwritev2",
    329: "pkey_mprotect",
    330: "pkey_alloc",
    331: "pkey_free",
    332: "statx",
    333: "io_pgetevents",
    334: "rseq",
    335: "pidfd_send_signal",
    336: "io_uring_setup",
    337: "io_uring_enter",
    338: "io_uring_register",
    339: "open_tree",
    340: "move_mount",
    341: "fsopen",
    342: "fsconfig",
    343: "fsmount",
    344: "fspick",
    345: "pidfd_open",
    346: "clone3",
    347: "close_range",
    348: "openat2",
    349: "pidfd_getfd",
    350: "faccessat2",
    351: "process_madvise",
    352: "epoll_pwait2",
    353: "mount_setattr",
    354: "quotactl_fd",
    355: "landlock_create_ruleset",
    356: "landlock_add_rule",
    357: "landlock_restrict_self",
    358: "memfd_secret",
    359: "process_mrelease",
    360: "futex_waitv",
    361: "set_mempolicy_home_node",
}

# 获取当前目录
current_dir = os.path.dirname(os.path.abspath(__file__))

# eBPF程序代码
BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cgroup.h>
#include <linux/kernfs.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/mount.h>
#include <linux/fs.h>

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

BPF_HASH(syscall_cnt, struct syscallcntkey, u64, 1024);
/*--------data structs end-----------*/

/*--------tools-----------*/
static int is_container_process(struct task_struct *task) {
    // 检查是否在非root命名空间
    if (task->nsproxy->pid_ns_for_children->level == 0) {
        return 0;
    }

    // 检查cgroup路径
    struct css_set *css = task->cgroups;
    struct cgroup_subsys_state *sbs = css->subsys[0];
    struct cgroup *cg = sbs->cgroup;
    struct kernfs_node *knode = cg->kn;
    struct kernfs_node *pknode = knode->parent;
    
    if (pknode == NULL) {
        return 0;
    }

    // 检查是否是容器相关的cgroup
    u8 cgroup_name[64];
    bpf_probe_read_str(&cgroup_name, sizeof(cgroup_name), knode->name);
    
    // 过滤掉系统cgroup
    if (strcmp(cgroup_name, "system.slice") == 0 ||
        strcmp(cgroup_name, "user.slice") == 0 ||
        strcmp(cgroup_name, "init.scope") == 0) {
        return 0;
    }

    return 1;
}

static int get_cid_core(struct task_struct *task, u8 *cid) {
    struct css_set *css = task->cgroups;
    struct cgroup_subsys_state *sbs = css->subsys[0];
    struct cgroup *cg = sbs->cgroup;
    struct kernfs_node *knode = cg->kn;
    struct kernfs_node *pknode = knode->parent;
    u8 tmp_cid[CONTAINER_ID_LEN];
    u8 *_cid;
    if (pknode != NULL) {
        u8 *aus = (u8 *)knode->name;
        bpf_probe_read_str(&tmp_cid, CONTAINER_ID_LEN, aus);
        if (tmp_cid[6] == '-')
            _cid = &tmp_cid[7];
        else
            _cid = (u8 *)&tmp_cid;
        bpf_probe_read_str(cid, CONTAINER_ID_USE_LEN, _cid);
    }
    return sizeof(cid);
}
/*--------tools end-----------*/

/*--------ebpf programs-----------*/
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct task_struct *curr_task = (struct task_struct *)bpf_get_current_task();
    
    // 检查是否是容器进程
    if (!is_container_process(curr_task)) {
        return 0;
    }

    struct syscallcntkey key = {};
    key.syscall_id = args->id;
    key.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(key.comm, sizeof(key.comm));
    get_cid_core((struct task_struct *)bpf_get_current_task(), key.cid);
    
    u64 *sys_cnt = syscall_cnt.lookup(&key);
    if (sys_cnt) {
        *sys_cnt += 1;
    } else {
        u64 one = 1;
        syscall_cnt.update(&key, &one);
    }
    
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    return 0;
}
/*--------ebpf programs end-----------*/
"""

# 定义数据结构
class SyscallCntKey(ctypes.Structure):
    _fields_ = [
        ("cid", ctypes.c_ubyte * 32),  # CONTAINER_ID_LEN
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),  # TASK_COMM_LEN
        ("syscall_id", ctypes.c_uint32)
    ]

def get_syscall_name(syscall_id):
    """获取系统调用名称，如果未知则返回ID"""
    return syscall_names.get(syscall_id, f"unknown({syscall_id})")

def format_container_id(cid):
    """格式化容器ID，移除空字符并限制长度"""
    cid = cid.strip()
    if len(cid) > 12:
        return cid[:12]
    return cid

def main():
    # 设置头文件路径和编译选项
    cflags = [
        f"-I{current_dir}",
        "-I/usr/include",
        "-I/usr/include/x86_64-linux-gnu",
        "-I/usr/src/linux-headers-$(uname -r)/include",
        "-I/usr/src/linux-headers-$(uname -r)/arch/x86/include",
        "-D__KERNEL__",
        "-D__ASM_SYSREG_H",
        "-Wno-compare-distinct-pointer-types",
        "-Wno-gnu-variable-sized-type-not-at-end",
        "-Wno-address-of-packed-member",
        "-Wno-tautological-compare",
        "-Wno-unknown-warning-option",
    ]

    # 定义需要过滤的终端相关系统调用
    terminal_syscalls = {
        "ioctl",           # 终端I/O控制
        "rt_sigprocmask",  # 信号处理
        "rt_sigaction",    # 信号处理
        "fstat",           # 文件状态
        "setpgid",         # 进程组设置
        "read",            # 终端读取
        "write",           # 终端写入
        "munmap",          # 内存管理
        "mprotect",        # 内存保护
        "access",          # 文件访问
        "openat",          # 文件打开
        "close",           # 文件关闭
        "mmap",            # 内存映射
        "brk",             # 内存分配
        "rseq",            # 重启序列
        "set_robust_list", # 健壮列表
        "prctl",           # 进程控制
        "statx",           # 文件状态
        "getpid",          # 获取进程ID
        "getgid",          # 获取组ID
        "getuid",          # 获取用户ID
        "geteuid",         # 获取有效用户ID
        "pipe2",           # 管道创建
        "newfstatat",      # 文件状态
        "statfs",          # 文件系统状态
    }

    # 加载eBPF程序
    b = BPF(text=BPF_PROGRAM, cflags=cflags)

    # 获取syscall_cnt映射
    syscall_cnt = b.get_table("syscall_cnt")

    print("开始监控系统调用...")
    print("按Ctrl+C退出")
    
    # 用于跟踪上次的系统调用统计
    last_stats = {}
    # 用于跟踪每个容器的当前系统调用及其时间戳
    container_syscalls = defaultdict(dict)
    # 用于存储容器名称
    container_names = {}
    # 用于存储累积的系统调用次数
    total_stats = defaultdict(lambda: defaultdict(int))
    # 用于存储活跃容器列表
    active_containers = set()
    # 用于存储每个容器的最后活跃时间
    container_last_active = {}
    # 用于存储每个容器的新系统调用
    container_new_syscalls = defaultdict(lambda: defaultdict(int))

    def get_container_name(container_id):
        if container_id not in container_names:
            try:
                cmd = f"docker inspect --format '{{{{.Name}}}}' {container_id} 2>/dev/null"
                name = os.popen(cmd).read().strip().lstrip('/')
                if name:
                    container_names[container_id] = name
                else:
                    container_names[container_id] = container_id
            except:
                container_names[container_id] = container_id
        return container_names[container_id]

    def print_container_stats(cid, width):
        container_name = get_container_name(cid)
        lines = []
        lines.append(f"容器: {cid} ({container_name})")
        lines.append("-" * width)
        lines.append(f"{'系统调用':<20} {'累积次数':<10} {'新增次数':<10} {'状态':<10}")
        lines.append("-" * width)
        
        # 按累积次数排序显示系统调用
        sorted_syscalls = sorted(total_stats[cid].items(), key=lambda x: x[1], reverse=True)
        for syscall_name, total_count in sorted_syscalls:
            # 显示所有系统调用，不仅仅是新的
            arrow = "←" if syscall_name in container_syscalls[cid] else ""
            new_count = container_new_syscalls[cid][syscall_name]
            lines.append(f"{syscall_name:<20} {total_count:<10} {new_count:<10} {arrow}")
        
        return lines

    try:
        while True:
            current_time = time.time()
            current_stats = {}
            has_updates = False
            
            # 清除超过10秒不活跃的容器
            active_containers = {cid for cid in active_containers 
                              if current_time - container_last_active.get(cid, 0) < 10}
            
            # 清除每个容器中超过1秒的系统调用箭头标记
            for cid in container_syscalls:
                container_syscalls[cid] = {k: v for k, v in container_syscalls[cid].items() 
                                         if current_time - v < 1.0}
            
            for key, value in syscall_cnt.items():
                k = SyscallCntKey()
                ctypes.memmove(ctypes.byref(k), bytes(key), ctypes.sizeof(k))
                
                cid = bytes(k.cid).decode('utf-8', errors='ignore').rstrip('\x00')
                cid = format_container_id(cid)
                
                syscall_id = k.syscall_id
                syscall_name = get_syscall_name(syscall_id)
                
                if syscall_name in terminal_syscalls:
                    continue
                
                stat_key = f"{cid}:{syscall_name}"
                current_stats[stat_key] = value.value
                
                # 更新累积统计
                old_total = total_stats[cid][syscall_name]
                total_stats[cid][syscall_name] = value.value
                
                # 检查是否有新的系统调用
                if stat_key not in last_stats:
                    container_new_syscalls[cid][syscall_name] = value.value
                    container_syscalls[cid][syscall_name] = current_time
                    container_last_active[cid] = current_time
                    active_containers.add(cid)
                    has_updates = True
                elif current_stats[stat_key] > last_stats[stat_key]:
                    container_new_syscalls[cid][syscall_name] += (current_stats[stat_key] - last_stats[stat_key])
                    container_syscalls[cid][syscall_name] = current_time
                    container_last_active[cid] = current_time
                    active_containers.add(cid)
                    has_updates = True

            # 始终显示所有活跃容器的信息
            if active_containers:
                term_width, term_height = os.get_terminal_size()
                
                print("\033[2J\033[H")
                print(f"\n=== 容器系统调用统计 [{time.strftime('%H:%M:%S')}] ===")
                print("=" * term_width)
                
                # 为每个容器准备显示内容
                all_container_lines = []
                for cid in sorted(active_containers):
                    container_lines = print_container_stats(cid, term_width)
                    all_container_lines.append(container_lines)
                
                # 计算每个容器可用的最大行数
                max_lines_per_container = (term_height - 5) // len(active_containers)
                
                # 显示每个容器的信息
                for container_lines in all_container_lines:
                    if len(container_lines) > max_lines_per_container:
                        print("\n".join(container_lines[:max_lines_per_container-1]))
                        print("...")
                    else:
                        print("\n".join(container_lines))
                    print("=" * term_width)
                
                if has_updates:
                    last_stats = current_stats.copy()
                    # 不清除container_new_syscalls，让它持续显示

            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n停止监控")
        sys.exit(0)

if __name__ == "__main__":
    main() 