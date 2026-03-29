// SPDX-License-Identifier: GPL-3.0
// XDR EDR — eBPF Monitor
// Hooks: sched_process_exec (argv capture), sys_enter_execve (argv),
//        kprobe/tcp_connect, BPF LSM: file_open, bprm_check_security,
//        kernel_module_request, sys_enter_memfd_create, sys_enter_ptrace,
//        sched_process_exit

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN    256
#define MAX_COMM_LEN    64
#define MAX_ARGV_LEN    256
#define MAX_ARGS        20
#define ALERT_CRITICAL  3
#define ALERT_WARNING   2
#define ALERT_INFO      1

// --- Event types ---
enum event_type {
    EVT_PROCESS_EXEC    = 1,
    EVT_FILE_OPEN       = 2,
    EVT_NET_CONNECT     = 3,
    EVT_MODULE_LOAD     = 4,
    EVT_PRIV_ESCALATION = 5,
    EVT_PROCESS_EXIT    = 6,
    EVT_MEMFD_CREATE    = 7,
    EVT_PTRACE          = 8,
};

// --- Event structure (sent to userspace) ---
struct edr_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;
    __u32 alert_level;
    __u32 ret_code;
    __u32 ppid;           // Parent PID
    char  comm[MAX_COMM_LEN];
    char  filename[MAX_PATH_LEN];
    char  argv[MAX_ARGV_LEN]; // Full command line arguments
    __u32 dst_ip;         // for net events
    __u16 dst_port;       // for net events
    __u16 _pad;
};

// --- Ring buffer for events ---
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 26);  // 64MB — argv buffer 256B
} events SEC(".maps");

// --- Blocklist: PIDs to kill ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // PID
    __type(value, __u8);   // 1 = block
} blocked_pids SEC(".maps");

// --- Blocklist: Module names ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[64]);
    __type(value, __u8);
} allowed_modules SEC(".maps");

// --- Blocklist: Destination IPs ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);    // IPv4 addr
    __type(value, __u8);   // 1 = block
} blocked_ips SEC(".maps");

// --- Temp storage for argv between sys_enter/exit_execve ---
struct argv_data {
    char buf[MAX_ARGV_LEN];
    __u16 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct argv_data);
} argv_store SEC(".maps");

// --- Sensitive paths for FIM (file_open) ---
// Checked inline in lsm_file_open

// Helper: get parent PID
static __always_inline __u32 get_ppid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    __u32 ppid = 0;

    if (!task)
        return 0;

    parent = BPF_CORE_READ(task, real_parent);
    if (parent)
        ppid = BPF_CORE_READ(parent, tgid);

    return ppid;
}

// Helper: emit event (base — no argv)
static __always_inline void emit_event(
    enum event_type type, __u32 alert, const char *fname,
    __u32 dst_ip, __u16 dst_port, __u32 ppid)
{
    struct edr_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid  = bpf_get_current_pid_tgid() >> 32;
    evt->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = uid_gid & 0xFFFFFFFF;
    evt->gid = uid_gid >> 32;

    evt->event_type  = type;
    evt->alert_level = alert;
    evt->ppid    = ppid;
    evt->dst_ip   = dst_ip;
    evt->dst_port = dst_port;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    if (fname)
        bpf_probe_read_kernel_str(&evt->filename, sizeof(evt->filename), fname);

    // argv is left zeroed for non-exec events
    evt->argv[0] = '\0';

    bpf_ringbuf_submit(evt, 0);
}

// Helper: emit exec event WITH argv
static __always_inline void emit_exec_event(
    __u32 alert, const char *fname, __u32 ppid,
    const char *argv_buf, __u16 argv_len)
{
    struct edr_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid  = bpf_get_current_pid_tgid() >> 32;
    evt->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    __u64 uid_gid = bpf_get_current_uid_gid();
    evt->uid = uid_gid & 0xFFFFFFFF;
    evt->gid = uid_gid >> 32;

    evt->event_type  = EVT_PROCESS_EXEC;
    evt->alert_level = alert;
    evt->ppid    = ppid;
    evt->dst_ip   = 0;
    evt->dst_port = 0;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    if (fname)
        bpf_probe_read_kernel_str(&evt->filename, sizeof(evt->filename), fname);

    // Copy captured argv
    if (argv_buf && argv_len > 0) {
        __u16 copy_len = argv_len;
        if (copy_len > MAX_ARGV_LEN - 1)
            copy_len = MAX_ARGV_LEN - 1;
        bpf_probe_read(&evt->argv, copy_len, argv_buf);
        evt->argv[copy_len] = '\0';
    } else {
        evt->argv[0] = '\0';
    }

    bpf_ringbuf_submit(evt, 0);
}



// ============================================================
// Hook 1: Process Execution — captures filename + PPID + argv
// ============================================================
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 ppid = get_ppid();

    // Read filename from tracepoint
    unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
    const char *fname = (const char *)ctx + fname_off;

    // Check if process is in blocklist
    __u8 *blocked = bpf_map_lookup_elem(&blocked_pids, &pid);
    if (blocked) {
        emit_event(EVT_PROCESS_EXEC, ALERT_CRITICAL, fname, 0, 0, ppid);
        bpf_send_signal(9);  // SIGKILL
        return 0;
    }

    // Capture argv from the current process mm->arg_start
    __u32 zero = 0;
    struct argv_data *adata = bpf_map_lookup_elem(&argv_store, &zero);
    if (adata) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task) {
            struct mm_struct *mm = BPF_CORE_READ(task, mm);
            if (mm) {
                unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
                unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
                unsigned long arg_len = arg_end - arg_start;

                if (arg_len > MAX_ARGV_LEN - 1)
                    arg_len = MAX_ARGV_LEN - 1;
                if (arg_len > 0 && arg_len < MAX_ARGV_LEN) {
                    long ret = bpf_probe_read_user(adata->buf, arg_len, (void *)arg_start);
                    if (ret == 0) {
                        adata->buf[arg_len] = '\0';
                        adata->len = (__u16)arg_len;

                        // Send raw argv (null-separated) — userspace
                        // handles null-to-space conversion
                        __u32 alert = (uid == 0) ? ALERT_WARNING : ALERT_INFO;
                        emit_exec_event(alert, fname, ppid, adata->buf, adata->len);
                        return 0;
                    }
                }
            }
        }
    }

    // Fallback: no argv captured
    __u32 alert = (uid == 0) ? ALERT_WARNING : ALERT_INFO;
    emit_event(EVT_PROCESS_EXEC, alert, fname, 0, 0, ppid);
    return 0;
}

// ============================================================
// Hook 2: TCP Connect (outbound connection detection)
// ============================================================
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    __u32 dst_ip = 0;
    __u16 dst_port = 0;
    bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &sk->__sk_common.skc_dport);
    dst_port = __builtin_bswap16(dst_port);

    __u32 ppid = get_ppid();

    // Check IP blocklist
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &dst_ip);
    __u32 alert = blocked ? ALERT_CRITICAL : ALERT_INFO;

    emit_event(EVT_NET_CONNECT, alert, NULL, dst_ip, dst_port, ppid);
    return 0;
}

// ============================================================
// Hook 3: BPF LSM — File Open (FIM with filename capture)
// ============================================================
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Only monitor root file access and specific sensitive files
    if (uid == 0) {
        // Try to get the file path from dentry
        struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
        if (dentry) {
            const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
            if (name) {
                emit_event(EVT_FILE_OPEN, ALERT_INFO, (const char *)name, 0, 0, get_ppid());
                return 0;
            }
        }
        emit_event(EVT_FILE_OPEN, ALERT_INFO, NULL, 0, 0, get_ppid());
    }
    return 0;  // 0 = allow, -EPERM = deny
}

// ============================================================
// Hook 4: BPF LSM — Module Load Control
// ============================================================
SEC("lsm/kernel_module_request")
int BPF_PROG(lsm_module_request, char *kmod_name, int order, char *origin)
{
    emit_event(EVT_MODULE_LOAD, ALERT_WARNING, kmod_name, 0, 0, get_ppid());
    return 0;
}

// ============================================================
// Hook 5: BPF LSM — Privilege Escalation Detection
// ============================================================
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm)
{
    // Capture the binary path being executed with elevated privileges
    const char *fname = BPF_CORE_READ(bprm, filename);
    emit_event(EVT_PRIV_ESCALATION, ALERT_INFO, fname, 0, 0, get_ppid());
    return 0;
}

// ============================================================
// Hook 6: Process Exit — for process lineage tracking
// ============================================================
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 ppid = get_ppid();

    emit_event(EVT_PROCESS_EXIT, ALERT_INFO, NULL, 0, 0, ppid);
    return 0;
}

// ============================================================
// Hook 7: memfd_create — Fileless malware detection
// ============================================================
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    // arg0 = const char *name
    const char *name = (const char *)ctx->args[0];
    __u32 ppid = get_ppid();

    emit_event(EVT_MEMFD_CREATE, ALERT_CRITICAL, name, 0, 0, ppid);
    return 0;
}

// ============================================================
// Hook 8: ptrace — Process injection detection
// ============================================================
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    // arg0 = request type, arg1 = target PID
    long request = ctx->args[0];
    __u32 target_pid = (__u32)ctx->args[1];
    __u32 ppid = get_ppid();

    // PTRACE_ATTACH=16, PTRACE_SEIZE=0x4206,
    // PTRACE_POKETEXT=4, PTRACE_POKEDATA=5
    __u32 alert = ALERT_INFO;
    if (request == 16 || request == 0x4206)  // ATTACH/SEIZE
        alert = ALERT_WARNING;
    if (request == 4 || request == 5)  // POKE TEXT/DATA (code injection)
        alert = ALERT_CRITICAL;

    // Store target PID in dst_ip field for reuse
    emit_event(EVT_PTRACE, alert, NULL, target_pid, (__u16)request, ppid);
    return 0;
}

// ============================================================
// Hook 9: init_module — Kernel module loading detection
// ============================================================
SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter *ctx)
{
    // init_module(void *module_image, unsigned long len, const char *param_values)
    // arg2 = param_values (module parameters string)
    __u32 ppid = get_ppid();
    const char *params = (const char *)ctx->args[2];

    emit_event(EVT_MODULE_LOAD, ALERT_CRITICAL, params, 0, 0, ppid);
    return 0;
}

// ============================================================
// Hook 10: finit_module — Kernel module loading from fd
// ============================================================
SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_finit_module(struct trace_event_raw_sys_enter *ctx)
{
    // finit_module(int fd, const char *param_values, int flags)
    // arg0 = fd, arg1 = param_values
    __u32 ppid = get_ppid();
    __u32 fd = (__u32)ctx->args[0];
    const char *params = (const char *)ctx->args[1];

    // Store fd in dst_ip for reference
    emit_event(EVT_MODULE_LOAD, ALERT_CRITICAL, params, fd, 0, ppid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
