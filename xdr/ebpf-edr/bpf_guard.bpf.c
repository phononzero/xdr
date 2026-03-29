// SPDX-License-Identifier: GPL-3.0
// XDR BPF Guard — LSM-based eBPF Access Control
//
// Restricts bpf() syscall to XDR processes only.
// Uses BPF LSM hooks: lsm/bpf, lsm/bpf_map, lsm/bpf_prog
//
// How it works:
//   1. XDR engine registers its PID and TGID into `xdr_allowed_pids` map
//   2. Any process calling bpf() is checked against the map
//   3. If not in the map → -EPERM (denied)
//   4. XDR processes and kernel threads are always allowed

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ALLOWED_PIDS  64
#define XDR_COMM_PREFIX   "python"  // XDR runs as python3

// ── Maps ────────────────────────────────────────────

// Map of allowed PIDs/TGIDs that can use bpf()
// Key: pid/tgid, Value: 1 = allowed
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ALLOWED_PIDS);
    __type(key, __u32);
    __type(value, __u32);
} xdr_allowed_pids SEC(".maps");

// Configuration: 0 = disabled (allow all), 1 = enforcing
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} guard_config SEC(".maps");

// Statistics: [0]=allowed, [1]=denied
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} guard_stats SEC(".maps");

// Denied event log (ring buffer)
struct denied_event {
    __u32 pid;
    __u32 uid;
    __u32 bpf_cmd;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} denied_events SEC(".maps");


// ── Helper: Check if PID is allowed ─────────────────

static __always_inline int is_allowed(void) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;  // TGID
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // Kernel threads (pid 0) are always allowed
    if (pid == 0)
        return 1;

    // Check guard_config — if not enforcing, allow all
    __u32 key = 0;
    __u32 *enforcing = bpf_map_lookup_elem(&guard_config, &key);
    if (!enforcing || *enforcing == 0)
        return 1;  // Guard not active yet

    // Check if TGID is in allowed PIDs map
    __u32 *allowed = bpf_map_lookup_elem(&xdr_allowed_pids, &pid);
    if (allowed && *allowed == 1)
        return 1;

    // Also check TID (for threaded XDR)
    if (tid != pid) {
        allowed = bpf_map_lookup_elem(&xdr_allowed_pids, &tid);
        if (allowed && *allowed == 1)
            return 1;
    }

    return 0;
}

static __always_inline void record_denied(__u32 cmd) {
    __u32 deny_key = 1;
    __u64 *cnt = bpf_map_lookup_elem(&guard_stats, &deny_key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    // Log denied event
    struct denied_event *evt = bpf_ringbuf_reserve(&denied_events,
                                                    sizeof(*evt), 0);
    if (evt) {
        evt->pid = bpf_get_current_pid_tgid() >> 32;
        evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        evt->bpf_cmd = cmd;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        bpf_ringbuf_submit(evt, 0);
    }
}

static __always_inline void record_allowed(void) {
    __u32 allow_key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&guard_stats, &allow_key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}


// ── LSM Hooks ───────────────────────────────────────

// Hook: bpf() syscall entry
// Restricts who can call bpf() at all
SEC("lsm/bpf")
int BPF_PROG(guard_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    if (is_allowed()) {
        record_allowed();
        return 0;
    }

    record_denied(cmd);
    return -1;  // EPERM
}

// Hook: BPF map operations
// Prevents unauthorized access to XDR's BPF maps
SEC("lsm/bpf_map")
int BPF_PROG(guard_bpf_map, struct bpf_map *map, fmode_t fmode)
{
    if (is_allowed())
        return 0;

    return -1;  // EPERM
}

// Hook: BPF program operations
// Prevents unauthorized loading/attachment of BPF programs
SEC("lsm/bpf_prog")
int BPF_PROG(guard_bpf_prog, struct bpf_prog *prog)
{
    if (is_allowed())
        return 0;

    return -1;  // EPERM
}

char LICENSE[] SEC("license") = "GPL";
