// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define GADGET_NO_BUF_RESERVE
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>

SEC("tracepoint/tail/tail_func0")
int tail_func0()
{
	bpf_printk("tail_func0 called");
	return 0;
}

SEC("tracepoint/tail/tail_func1")
int tail_func1()
{
	bpf_printk("tail_func1 called");
	return 0;
}

// SEC("freplace/subprog") int replacement_func0() {
// 	bpf_printk("replacement_func0 called");
// 	return 0;
// }

// prog array for tail calls
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 4);
	__type(key, u32);
	__type(value, u32);
	__array(values, int());
} tail_calls SEC(".maps") = {
	.values = {
        [0] = &tail_func0,
        [1] = &tail_func1,
    },

};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(exec, events, event);

static __attribute__((noinline)) int subprog(struct trace_event_raw_sched_process_exec *ctx) {
    bpf_printk("subprog called");    
	u32 key = 0;
	bpf_tail_call(ctx, &tail_calls, key);
    return 0;
}

// tracepoint/sched/sched_process_exec is called after a successful execve
SEC("tracepoint/sched/sched_process_exec")
int ig_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	u32 pre_sched_pid = ctx->old_pid;
	//struct event *event;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);

	bpf_printk("execve: parent=%d oldpid=%d newpid=%d",
		   BPF_CORE_READ(parent, tgid), pre_sched_pid,
		   BPF_CORE_READ(task, tgid));

	bpf_printk("tracepoint: step 1");
	subprog(ctx);
	bpf_printk("tracepoint: step 2");

	u32 key = 1;
	bpf_tail_call(ctx, &tail_calls, key);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
