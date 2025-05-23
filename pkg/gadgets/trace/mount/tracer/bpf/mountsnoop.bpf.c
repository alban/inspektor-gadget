/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "mountsnoop.h"
#include <gadget/mntns.h>
#include <gadget/mntns_filter.h>

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;

// we need this to make sure the compiler doesn't remove our struct
const struct event *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct arg);
} args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct event);
} heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// TODO: have to use "inline" to avoid this error:
// bpf/mountsnoop.bpf.c:41:12: error: defined with too many args
// static int probe_entry(const char *src, const char *dest, const char *fs,
static __always_inline int probe_entry(const char *src, const char *dest,
				       const char *fs, __u64 flags,
				       const char *data, enum op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct arg arg = {};
	u64 mntns_id;

	mntns_id = gadget_get_current_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	if (target_pid && target_pid != pid)
		return 0;

	arg.ts = bpf_ktime_get_ns();
	arg.flags = flags;
	arg.src = src;
	arg.dest = dest;
	arg.fs = fs;
	arg.data = data;
	arg.op = op;
	bpf_map_update_elem(&args, &tid, &arg, BPF_ANY);

	return 0;
};

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct arg *argp;
	struct event *eventp;
	int zero = 0;
	u64 mntns_id;

	argp = bpf_map_lookup_elem(&args, &tid);
	if (!argp)
		return 0;

	eventp = bpf_map_lookup_elem(&heap, &zero);
	if (!eventp)
		goto cleanup;

	eventp->mount_ns_id = gadget_get_current_mntns_id();
	eventp->timestamp = bpf_ktime_get_boot_ns();
	eventp->delta = bpf_ktime_get_ns() - argp->ts;
	eventp->flags = argp->flags;
	eventp->pid = pid;
	eventp->tid = tid;
	eventp->ret = ret;
	eventp->op = argp->op;
	bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));
	if (argp->src)
		bpf_probe_read_user_str(eventp->src, sizeof(eventp->src),
					argp->src);
	else
		eventp->src[0] = '\0';
	if (argp->dest)
		bpf_probe_read_user_str(eventp->dest, sizeof(eventp->dest),
					argp->dest);
	else
		eventp->dest[0] = '\0';
	if (argp->fs)
		bpf_probe_read_user_str(eventp->fs, sizeof(eventp->fs),
					argp->fs);
	else
		eventp->fs[0] = '\0';
	if (argp->data)
		bpf_probe_read_user_str(eventp->data, sizeof(eventp->data),
					argp->data);
	else
		eventp->data[0] = '\0';

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, eventp,
			      sizeof(*eventp));

cleanup:
	bpf_map_delete_elem(&args, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int ig_mount_e(struct syscall_trace_enter *ctx)
{
	const char *src = (const char *)ctx->args[0];
	const char *dest = (const char *)ctx->args[1];
	const char *fs = (const char *)ctx->args[2];
	__u64 flags = (__u64)ctx->args[3];
	const char *data = (const char *)ctx->args[4];

	return probe_entry(src, dest, fs, flags, data, MOUNT);
}

SEC("tracepoint/syscalls/sys_exit_mount")
int ig_mount_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_umount")
int ig_umount_e(struct syscall_trace_enter *ctx)
{
	const char *dest = (const char *)ctx->args[0];
	__u64 flags = (__u64)ctx->args[1];

	return probe_entry(NULL, dest, NULL, flags, NULL, UMOUNT);
}

SEC("tracepoint/syscalls/sys_exit_umount")
int ig_umount_x(struct syscall_trace_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
