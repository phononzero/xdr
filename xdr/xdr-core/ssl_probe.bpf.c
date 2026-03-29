// SPDX-License-Identifier: GPL-3.0
// XDR SSL/TLS Uprobe — plaintext capture before encryption / after decryption
// Hooks: OpenSSL SSL_write/SSL_read, GnuTLS gnutls_record_send/recv
//
// This captures the PLAINTEXT data that applications send/receive through
// TLS connections. Since we hook BEFORE encryption (SSL_write) and AFTER
// decryption (SSL_read), we see the unencrypted content.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_DATA_SIZE 4096
#define MAX_COMM_SIZE 16

// Event structure sent to userspace
struct ssl_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 len;            // actual data length
    __u32 buf_filled;     // bytes captured (min of len, MAX_DATA_SIZE)
    __u8  direction;      // 0=write (outgoing), 1=read (incoming)
    char  comm[MAX_COMM_SIZE];
    __u8  data[MAX_DATA_SIZE];
};

// Temporary storage for uprobe entry → uretprobe return correlation
struct ssl_args {
    __u64 buf_ptr;        // pointer to plaintext buffer
    __u32 len;            // requested length
    __u8  direction;      // 0=write, 1=read
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB ring buffer
} ssl_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);               // pid_tgid
    __type(value, struct ssl_args);
} active_ssl_args SEC(".maps");

// ── Helper: get pid_tgid key ────────────────────────────

static __always_inline __u64 get_pid_tgid(void)
{
    return bpf_get_current_pid_tgid();
}

// ── SSL_write entry: capture buffer pointer before encryption ──

static __always_inline int ssl_write_enter(void *ctx, void *ssl,
                                            const void *buf, int num)
{
    struct ssl_args args = {};
    __u64 pid_tgid = get_pid_tgid();

    args.buf_ptr = (__u64)buf;
    args.len = (__u32)num;
    args.direction = 0;  // write = outgoing

    bpf_map_update_elem(&active_ssl_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// ── SSL_write return: on success, emit captured data ────

static __always_inline int ssl_write_return(void *ctx, int ret)
{
    __u64 pid_tgid = get_pid_tgid();
    struct ssl_args *args;
    struct ssl_event *event;

    args = bpf_map_lookup_elem(&active_ssl_args, &pid_tgid);
    if (!args)
        return 0;

    if (ret <= 0)
        goto cleanup;

    event = bpf_ringbuf_reserve(&ssl_events, sizeof(*event), 0);
    if (!event)
        goto cleanup;

    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->uid = bpf_get_current_uid_gid() >> 32;
    event->direction = args->direction;
    event->len = (__u32)ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Capture plaintext data (limit to MAX_DATA_SIZE)
    __u32 copy_len = (__u32)ret;
    if (copy_len > MAX_DATA_SIZE)
        copy_len = MAX_DATA_SIZE;
    event->buf_filled = copy_len;

    if (args->buf_ptr) {
        bpf_probe_read_user(&event->data, copy_len, (void *)args->buf_ptr);
    }

    bpf_ringbuf_submit(event, 0);

cleanup:
    bpf_map_delete_elem(&active_ssl_args, &pid_tgid);
    return 0;
}

// ── SSL_read entry: capture buffer pointer (data arrives on return) ──

static __always_inline int ssl_read_enter(void *ctx, void *ssl,
                                           void *buf, int num)
{
    struct ssl_args args = {};
    __u64 pid_tgid = get_pid_tgid();

    args.buf_ptr = (__u64)buf;
    args.len = (__u32)num;
    args.direction = 1;  // read = incoming

    bpf_map_update_elem(&active_ssl_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// ── SSL_read return: buffer now contains decrypted data ──

static __always_inline int ssl_read_return(void *ctx, int ret)
{
    // Same logic as write return — data is in the buffer now
    return ssl_write_return(ctx, ret);
}

// ── OpenSSL uprobes ────────────────────────────────────

// int SSL_write(SSL *ssl, const void *buf, int num)
SEC("uprobe/SSL_write")
int BPF_UPROBE(uprobe_ssl_write, void *ssl, const void *buf, int num)
{
    return ssl_write_enter(ctx, ssl, buf, num);
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(uretprobe_ssl_write, int ret)
{
    return ssl_write_return(ctx, ret);
}

// int SSL_read(SSL *ssl, void *buf, int num)
SEC("uprobe/SSL_read")
int BPF_UPROBE(uprobe_ssl_read, void *ssl, void *buf, int num)
{
    return ssl_read_enter(ctx, ssl, buf, num);
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(uretprobe_ssl_read, int ret)
{
    return ssl_read_return(ctx, ret);
}

// ── GnuTLS uprobes ────────────────────────────────────

// ssize_t gnutls_record_send(gnutls_session_t session, const void *data, size_t sizeofdata)
SEC("uprobe/gnutls_record_send")
int BPF_UPROBE(uprobe_gnutls_send, void *session, const void *data, size_t sizeofdata)
{
    return ssl_write_enter(ctx, session, data, (int)sizeofdata);
}

SEC("uretprobe/gnutls_record_send")
int BPF_URETPROBE(uretprobe_gnutls_send, int ret)
{
    return ssl_write_return(ctx, ret);
}

// ssize_t gnutls_record_recv(gnutls_session_t session, void *data, size_t sizeofdata)
SEC("uprobe/gnutls_record_recv")
int BPF_UPROBE(uprobe_gnutls_recv, void *session, void *data, size_t sizeofdata)
{
    return ssl_read_enter(ctx, session, data, (int)sizeofdata);
}

SEC("uretprobe/gnutls_record_recv")
int BPF_URETPROBE(uretprobe_gnutls_recv, int ret)
{
    return ssl_read_return(ctx, ret);
}

char _license[] SEC("license") = "GPL";
