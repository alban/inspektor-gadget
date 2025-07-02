/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2016 Brendan Gregg */
/* Copyright (c) 2022-2023 Rong Tao */
/* Copyright (c) 2025 The Inspektor Gadget authors */

/* Initially based on BCC ttysnoop tool, which is
 * https://github.com/iovisor/bcc/blob/master/tools/ttysnoop.py
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/types.h>
#include <gadget/filesystem.h>

#define MAX_BUF_SIZE 8192

//extern int LINUX_KERNEL_VERSION __kconfig;

// enum iter_type is defined in vmlinux.h but without ITER_UBUF because it was
// added in Linux v6.0.
// https://github.com/torvalds/linux/commit/fcb14cb1bdacec5b4374fe161e83fb8208164a85
enum iter_type___v6_0 {
	/* iter types */
	ITER_IOVEC___v6_0,
	ITER_KVEC___v6_0,
	ITER_BVEC___v6_0,
	ITER_XARRAY___v6_0,
	ITER_DISCARD___v6_0,
	ITER_UBUF___v6_0,
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;

	u32 len;
	char buf[MAX_BUF_SIZE];
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(ttysnoop, events, event);

SEC("kprobe/tty_write")
int BPF_KPROBE(tty_write_e, struct kiocb *iocb, struct iov_iter *from)
{
	const struct kvec *kvec;
	struct event *event;

	if (gadget_should_discard_data_current())
		return 0;

	bpf_printk("tty_write: starting\n");

	event = gadget_reserve_buf(&events, sizeof(struct event));
	if (!event)
		return 0;

	gadget_process_populate(&event->proc);
	event->timestamp_raw = bpf_ktime_get_boot_ns();

	if (!bpf_core_field_exists(from->iter_type))
		return 0;

	enum iter_type___v6_0 type = BPF_CORE_READ(from, iter_type);
	bpf_printk("tty_write: iter_type: %d\n", type);

	if (bpf_core_enum_value_exists(enum iter_type___v6_0,
				       ITER_UBUF___v6_0) &&
	    type == bpf_core_enum_value(enum iter_type___v6_0,
					ITER_UBUF___v6_0)) {
		const struct iovec *iovec =
			(const struct iovec *)&from->__ubuf_iovec;
		bpf_probe_read_user(&event->buf, sizeof(event->buf),
				    &from->__ubuf_iovec.iov_base);
		bpf_probe_read_user(&event->len, sizeof(event->len),
				    &from->__ubuf_iovec.iov_len);
	}

	bpf_printk("tty_write: len: %u data: %c\n", event->len, event->buf[0]);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
