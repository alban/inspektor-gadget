// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2022 The Inspektor Gadget authors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GADGET_TYPE_NETWORKING
#include "sockets-map.h"

// Linux only supports scalars and pointers to ctx (e.g. 'struct __sk_buff *'
// for socket filter) in bpf extensions so we can't pass all fields in one
// call.
//
// This might have a small performance penalty, but this is easier than using a
// separate ring buffer to send the metadata in userspace.

SEC("freplace/gadget_skb_get_mntns")
__u64 gadget_skb_get_mntns(struct __sk_buff *skb)
{
	struct sockets_value *socketp = gadget_socket_lookup(skb);
	if (socketp != NULL)
		return socketp->mntns;

	return 0;
}

SEC("freplace/gadget_skb_get_pid_tgid")
__u64 gadget_skb_get_pid_tgid(struct __sk_buff *skb)
{
	struct sockets_value *socketp = gadget_socket_lookup(skb);
	if (socketp != NULL)
		return socketp->pid_tgid;

	return 0;
}

SEC("freplace/gadget_skb_get_comm1")
__u64 gadget_skb_get_comm1(struct __sk_buff *skb)
{
	struct sockets_value *socketp = gadget_socket_lookup(skb);
	if (socketp != NULL)
		return *(__u64 *)socketp->task;

	return 0;
}

SEC("freplace/gadget_skb_get_comm2")
__u64 gadget_skb_get_comm2(struct __sk_buff *skb)
{
	struct sockets_value *socketp = gadget_socket_lookup(skb);
	if (socketp != NULL)
		return *(__u64 *)(socketp->task + 8);

	return 0;
}

char _license[] SEC("license") = "GPL";
