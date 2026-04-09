// netprobe.bpf.c - eBPF probes for network connection tracking
// Hooks: tcp_v4_connect, inet_csk_accept, udp_sendmsg
//
// Compiled and loaded by BCC (bcc-tools). Do not compile standalone.

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// ─── Event structure sent to userspace ──────────────────────────────────────

#define TASK_COMM_LEN 16
#define PROTO_TCP 6
#define PROTO_UDP 17

struct conn_event_t {
    u64  ts_ns;             // ktime_get_ns() at event time
    u32  pid;
    u32  uid;
    char comm[TASK_COMM_LEN];
    u32  saddr;             // source IPv4 (network byte order)
    u32  daddr;             // destination IPv4 (network byte order)
    u16  sport;             // source port (host byte order)
    u16  dport;             // destination port (host byte order)
    u8   proto;             // PROTO_TCP or PROTO_UDP
    u8   direction;         // 0 = outbound (connect), 1 = inbound (accept)
};

BPF_PERF_OUTPUT(conn_events);

// ─── Temporary map to stash sock* across tcp_v4_connect entry/return ────────

BPF_HASH(tcp_connect_pending, u64, struct sock *);

// ─── tcp_v4_connect entry: save sock* keyed by pid+tgid ─────────────────────

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
    u64 id = bpf_get_current_pid_tgid();
    tcp_connect_pending.update(&id, &sk);
    return 0;
}

// ─── tcp_v4_connect return: read filled-in sock and emit event ───────────────

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    if (ret != 0)
        return 0;   // connect failed, ignore

    u64 id = bpf_get_current_pid_tgid();
    struct sock **skpp = tcp_connect_pending.lookup(&id);
    if (!skpp)
        return 0;

    struct sock *sk = *skpp;
    tcp_connect_pending.delete(&id);

    struct inet_sock *inet = inet_sk(sk);

    struct conn_event_t evt = {};
    evt.ts_ns    = bpf_ktime_get_ns();
    evt.pid      = id >> 32;
    evt.uid      = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.proto    = PROTO_TCP;
    evt.direction = 0;  // outbound

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // Read addresses — use bpf_probe_read for older kernels
    bpf_probe_read_kernel(&evt.saddr, sizeof(evt.saddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr), &inet->inet_daddr);
    bpf_probe_read_kernel(&evt.sport, sizeof(evt.sport), &inet->inet_sport);
    bpf_probe_read_kernel(&evt.dport, sizeof(evt.dport), &inet->inet_dport);

    // Ports are stored in network byte order in the kernel; convert to host
    evt.sport = ntohs(evt.sport);
    evt.dport = ntohs(evt.dport);

    conn_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ─── inet_csk_accept return: inbound TCP connection accepted ─────────────────

int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk)
        return 0;

    struct inet_sock *inet = inet_sk(sk);

    struct conn_event_t evt = {};
    evt.ts_ns     = bpf_ktime_get_ns();
    u64 id        = bpf_get_current_pid_tgid();
    evt.pid       = id >> 32;
    evt.uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.proto     = PROTO_TCP;
    evt.direction = 1;  // inbound

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_probe_read_kernel(&evt.saddr, sizeof(evt.saddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr), &inet->inet_daddr);
    bpf_probe_read_kernel(&evt.sport, sizeof(evt.sport), &inet->inet_sport);
    bpf_probe_read_kernel(&evt.dport, sizeof(evt.dport), &inet->inet_dport);

    evt.sport = ntohs(evt.sport);
    evt.dport = ntohs(evt.dport);

    conn_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// ─── udp_sendmsg: outbound UDP datagram ──────────────────────────────────────

int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk,
                        struct msghdr *msg, size_t len)
{
    struct inet_sock *inet = inet_sk(sk);

    struct conn_event_t evt = {};
    evt.ts_ns     = bpf_ktime_get_ns();
    u64 id        = bpf_get_current_pid_tgid();
    evt.pid       = id >> 32;
    evt.uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    evt.proto     = PROTO_UDP;
    evt.direction = 0;  // outbound

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    bpf_probe_read_kernel(&evt.saddr, sizeof(evt.saddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr), &inet->inet_daddr);
    bpf_probe_read_kernel(&evt.sport, sizeof(evt.sport), &inet->inet_sport);
    bpf_probe_read_kernel(&evt.dport, sizeof(evt.dport), &inet->inet_dport);

    evt.sport = ntohs(evt.sport);
    evt.dport = ntohs(evt.dport);

    conn_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
