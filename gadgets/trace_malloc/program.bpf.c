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
	malloc,
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

	gadget_user_stack user_stack_id_raw;
	__u64 inode;
	__u64 mtime_sec;
	__u32 mtime_nsec;

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

const volatile bool with_user_stack = false;
GADGET_PARAM(with_user_stack);

static __always_inline int gen_alloc_enter(size_t size)
{
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);

	return 0;
}

struct inode___with_timespec64 {
	struct timespec64 i_mtime;
};

struct inode___without_timespec64 {
	time64_t i_mtime_sec;
	u32 i_mtime_nsec;
};

static __always_inline void set_user_stack(struct pt_regs *ctx, struct event *event)
{
	if (!with_user_stack) {
		event->user_stack_id_raw = -1;
		return;
	}

	event->user_stack_id_raw = gadget_get_user_stack(ctx);

	struct task_struct *task =
		(struct task_struct *)bpf_get_current_task();
	struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
	event->inode = (u64)BPF_CORE_READ(inode, i_ino);

	// Linux v6.10 commit 3aa63a569c64e708df547a8913c84e64a06e7853
	struct inode___without_timespec64 *inode_without_timespec64 = (struct inode___without_timespec64 *)inode;
	struct inode___with_timespec64 *inode_with_timespec64 = (struct inode___with_timespec64 *)inode;

	if (bpf_core_field_exists(inode_without_timespec64->i_mtime_sec)) {
		event->mtime_sec = BPF_CORE_READ(inode_without_timespec64, i_mtime_sec);
		event->mtime_nsec = BPF_CORE_READ(inode_without_timespec64, i_mtime_nsec);
	}
	if (bpf_core_field_exists(inode_with_timespec64->i_mtime)) {
		event->mtime_sec = BPF_CORE_READ(inode_with_timespec64, i_mtime.tv_sec);
		event->mtime_nsec = BPF_CORE_READ(inode_with_timespec64, i_mtime.tv_nsec);
	}
}

static __always_inline int gen_alloc_exit(struct pt_regs *ctx,
					  enum memop operation, u64 addr)
{
	struct event *event;
	u64 pid_tgid;
	u32 tid;
	u64 *size_ptr;
	u64 size;

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

    set_user_stack(ctx, event);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

static __always_inline int gen_free_enter(struct pt_regs *ctx,
					  enum memop operation, u64 addr)
{
	struct event *event;

	if (gadget_should_discard_data_current())
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->operation_raw = operation;
	event->addr = addr;
	event->size = 0;
	event->timestamp_raw = bpf_ktime_get_ns();

    set_user_stack(ctx, event);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

/* common macros */
#define PROBE_RET_VAL_FOR_ALLOC(func)                              \
	SEC("uretprobe/libc:" #func)                               \
	int trace_uretprobe_##func(struct pt_regs *ctx)            \
	{                                                          \
		return gen_alloc_exit(ctx, func, PT_REGS_RC(ctx)); \
	}

/* malloc */
SEC("uprobe/libc:malloc")
int BPF_UPROBE(trace_uprobe_malloc, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(malloc)

/* free */
SEC("uprobe/libc:free")
int BPF_UPROBE(trace_uprobe_free, void *address)
{
	return gen_free_enter(ctx, free, (u64)address);
}

/* calloc */
SEC("uprobe/libc:calloc")
int BPF_UPROBE(trace_uprobe_calloc, size_t nmemb, size_t size)
{
	return gen_alloc_enter(nmemb * size);
}

PROBE_RET_VAL_FOR_ALLOC(calloc)

/* realloc */
SEC("uprobe/libc:realloc")
int BPF_UPROBE(trace_uprobe_realloc, void *ptr, size_t size)
{
	gen_free_enter(ctx, realloc_free, (u64)ptr);
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(realloc)

/* mmap */
SEC("uprobe/libc:mmap")
int BPF_UPROBE(trace_uprobe_mmap, void *address, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(mmap)

/* munmap */
SEC("uprobe/libc:munmap")
int BPF_UPROBE(trace_uprobe_munmap, void *address)
{
	return gen_free_enter(ctx, munmap, (u64)address);
}

/* posix_memalign */
SEC("uprobe/libc:posix_memalign")
int BPF_UPROBE(trace_uprobe_posix_memalign, void **memptr, size_t alignment,
	       size_t size)
{
	u64 memptr64;
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	memptr64 = (u64)memptr;
	bpf_map_update_elem(&memptrs, &tid, &memptr64, BPF_ANY);

	return gen_alloc_enter(size);
}

SEC("uretprobe/libc:posix_memalign")
int trace_uretprobe_posix_memalign(struct pt_regs *ctx)
{
	u64 *memptr64;
	void *addr;
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();

	memptr64 = bpf_map_lookup_elem(&memptrs, &tid);
	if (!memptr64)
		return 0;
	bpf_map_delete_elem(&memptrs, &tid);

	if (bpf_probe_read_user(&addr, sizeof(void *), (void *)*memptr64))
		return 0;

	return gen_alloc_exit(ctx, posix_memalign, (u64)addr);
}

/* aligned_alloc */
SEC("uprobe/libc:aligned_alloc")
int BPF_UPROBE(trace_uprobe_aligned_alloc, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(aligned_alloc)

/* valloc */
SEC("uprobe/libc:valloc")
int BPF_UPROBE(trace_uprobe_valloc, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(valloc)

/* memalign */
SEC("uprobe/libc:memalign")
int BPF_UPROBE(trace_uprobe_memalign, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(memalign)

/* pvalloc */
SEC("uprobe/libc:pvalloc")
int BPF_UPROBE(trace_uprobe_pvalloc, size_t size)
{
	return gen_alloc_enter(size);
}

PROBE_RET_VAL_FOR_ALLOC(pvalloc)

char LICENSE[] SEC("license") = "Dual BSD/GPL";
