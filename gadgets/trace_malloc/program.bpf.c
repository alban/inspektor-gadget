// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/types.h>
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/user_stack_map.h>

#define MAX_ENTRIES 10240

enum memop {
	allocate_memory,
	free,
	calloc,
	realloc,
	realloc_free,
	mmap,
	munmap,
	posix_memalign,
	aligned_alloc,
	valloc,
	memalign,
	pvalloc,
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	struct gadget_user_stack ustack;

	enum memop operation_raw;
	__u64 addr;
	__u64 size;
};

/* used for context between uprobes and uretprobes of allocations */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64);
} sizes SEC(".maps");

/* used by posix_memalign */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64);
} memptrs SEC(".maps");

/**
 * clean up the maps when a thread terminates,
 * because there may be residual data in the map
 * if a userspace thread is killed between a uprobe and a uretprobe
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&sizes, &tid);
	bpf_map_delete_elem(&memptrs, &tid);
	return 0;
}

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(malloc, events, event);

static __always_inline int gen_alloc_enter(size_t size)
{
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);

	return 0;
}

static __always_inline int gen_alloc_exit(struct pt_regs *ctx,
					  enum memop operation, u64 addr)
{
	struct event *event;
	u64 pid_tgid;
	u32 tid;
	u64 *size_ptr;
	u64 size;

	bpf_printk("gen_alloc_exit called with operation=%d, addr=0x%llx\n", operation, addr);

	if (gadget_should_discard_data_current())
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;
	size_ptr = bpf_map_lookup_elem(&sizes, &tid);
	if (!size_ptr)
		return 0;
	size = *size_ptr;
	bpf_map_delete_elem(&sizes, &tid);

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->operation_raw = operation;
	event->addr = addr;
	event->size = size;
	event->timestamp_raw = bpf_ktime_get_ns();

	gadget_get_user_stack(ctx, &event->ustack);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

/* common macros */
#define PROBE_RET_VAL_FOR_ALLOC(func)                              \
	SEC("uretprobe//home/alban/test/python-and-c-lib/libmylib.so:" #func)                               \
	int trace_uretprobe_##func(struct pt_regs *ctx)            \
	{                                                          \
		return gen_alloc_exit(ctx, func, PT_REGS_RC(ctx)); \
	}

/* malloc */
SEC("uprobe//home/alban/test/python-and-c-lib/libmylib.so:allocate_memory")
int BPF_UPROBE(trace_uprobe_malloc, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(allocate_memory)


char LICENSE[] SEC("license") = "Dual BSD/GPL";
