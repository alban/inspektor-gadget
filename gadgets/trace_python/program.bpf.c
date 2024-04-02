// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/filesystem.h>

enum op {
	ENTER,
	RETURN,
};

struct event {
	gadget_mntns_id mntns_id;
	__u32 pid;
	__u8 comm[TASK_COMM_LEN];
	enum op operation;
	__u8 filename[MAX_STRING_SIZE];
	__u8 funcname[MAX_STRING_SIZE];
	__u64 lineno;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(python, events, event);

static __always_inline int submit_event(struct pt_regs *ctx,
					      enum op operation)
{
	u64 mntns_id;
	struct event *event;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->mntns_id = mntns_id;
	event->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	event->operation = operation;

	// readelf -n /usr/bin/python3
	// Arguments: 8@%r14 8@%r15 -4@%eax
#ifdef bpf_target_x86
	bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *) ctx->r14);
	bpf_probe_read_user_str(event->funcname, sizeof(event->funcname), (void *) ctx->r15);
	event->lineno = ctx->ax;
#endif

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

SEC("usdt//usr/bin/python3:python:function__entry")
int trace_usdt_entry(struct pt_regs *ctx)
{
	return submit_event(ctx, ENTER);
}

SEC("usdt//usr/bin/python3:python:function__return")
int trace_usdt_return(struct pt_regs *ctx)
{
	return submit_event(ctx, RETURN);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
