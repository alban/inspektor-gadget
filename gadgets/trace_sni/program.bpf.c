// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021-2022 The Inspektor Gadget authors */
/* Copyright (c) 2021-2022 SAP SE or an SAP affiliate company and Gardener contributors */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GADGET_NO_BUF_RESERVE
#define GADGET_MAX_EVENT_SIZE 512
#define GADGET_TYPE_NETWORKING
#include <gadget/macros.h>
#include <gadget/buffer.h>
#include <gadget/types.h>
#include <gadget/sockets-map.h>
#include <gadget/filter.h>

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x1
#define TLS_EXTENSION_SERVER_NAME 0x0
// TODO: Figure out real max number according to RFC.
#define TLS_MAX_EXTENSION_COUNT 20
// TODO: figure out the right value.
#define TLS_MAX_SERVER_NAME_LEN 128

// The length of the session ID length field.
#define TLS_SESSION_ID_LENGTH_LEN 1
// The length of the cipher suites length field.
#define TLS_CIPHER_SUITES_LENGTH_LEN 2
// The length of the compression methods length field.
#define TLS_COMPRESSION_METHODS_LENGTH_LEN 1
// The length of the extensions length field.
#define TLS_EXTENSIONS_LENGTH_LEN 2
// The length of the extension type field.
#define TLS_EXTENSION_TYPE_LEN 2
// The length of the extension length field (a single extension).
#define TLS_EXTENSION_LENGTH_LEN 2

// The offset of the server name length field from the start of the server_name
// TLS extension.
#define TLS_SERVER_NAME_LENGTH_OFF 7
// The offset of the server name field from the start of the server_name TLS
// extension.
#define TLS_SERVER_NAME_OFF 9

// The offset of the handshake type field from the start of the TLS payload.
#define TLS_HANDSHAKE_TYPE_OFF 5
// The offset of the session ID length field from the start of the TLS payload.
#define TLS_SESSION_ID_LENGTH_OFF 43

struct event_t {
	gadget_timestamp timestamp_raw;
	gadget_netns_id netns_id;
	struct gadget_process proc;

	char name[TLS_MAX_SERVER_NAME_LEN];
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(sni, events, event_t);

// parse_sni() from:
// https://github.com/gardener/connectivity-monitor/blob/4e924f50367c9fa02075b50b0ecd8c821b3a15f1/connectivity-exporter/packet/c/cap.c#L146-L149

// Parses the provided SKB at the given offset for SNI information. If parsing
// succeeds, the SNI information is written to the out array. Returns the
// number of characters in the SNI field or 0 if SNI couldn't be parsed.
static __always_inline int parse_sni(struct __sk_buff *skb, int data_offset,
				     char *out)
{
	// Verify TLS content type.
	__u8 content_type;
	bpf_skb_load_bytes(skb, data_offset, &content_type, 1);
	if (content_type != TLS_CONTENT_TYPE_HANDSHAKE)
		return 0;

	// Verify TLS handshake type.
	__u8 handshake_type;
	bpf_skb_load_bytes(skb, data_offset + TLS_HANDSHAKE_TYPE_OFF,
			   &handshake_type, 1);
	if (handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
		return 0;

	int session_id_len_off = data_offset + TLS_SESSION_ID_LENGTH_OFF;
	__u8 session_id_len;
	bpf_skb_load_bytes(skb, session_id_len_off, &session_id_len, 1);

	int cipher_suites_len_off =
		session_id_len_off + TLS_SESSION_ID_LENGTH_LEN + session_id_len;
	__u16 cipher_suites_len_be;
	bpf_skb_load_bytes(skb, cipher_suites_len_off, &cipher_suites_len_be,
			   2);

	int compression_methods_len_off = cipher_suites_len_off +
					  TLS_CIPHER_SUITES_LENGTH_LEN +
					  bpf_ntohs(cipher_suites_len_be);

	__u8 compression_methods_len;
	bpf_skb_load_bytes(skb, compression_methods_len_off,
			   &compression_methods_len, 1);

	int extensions_len_off = compression_methods_len_off +
				 TLS_COMPRESSION_METHODS_LENGTH_LEN +
				 compression_methods_len;

	int extensions_off = extensions_len_off + TLS_EXTENSIONS_LENGTH_LEN;

	// TODO: Ensure the cursor doesn't surpass the extensions length value?
	__u16 cur = 0;
	__u16 server_name_ext_off = 0;
	for (int i = 0; i < TLS_MAX_EXTENSION_COUNT; i++) {
		__u16 curr_ext_type_be;
		bpf_skb_load_bytes(skb, extensions_off + cur, &curr_ext_type_be,
				   2);
		if (bpf_ntohs(curr_ext_type_be) == TLS_EXTENSION_SERVER_NAME) {
			server_name_ext_off = extensions_off + cur;
			break;
		}
		// Skip the extension type field to get to the extension length field.
		cur += TLS_EXTENSION_TYPE_LEN;

		// Read the extension length and skip the extension length field as well as
		// the rest of the extension to get to the next extension.
		__u16 len_be;
		bpf_skb_load_bytes(skb, extensions_off + cur, &len_be, 2);
		cur += TLS_EXTENSION_LENGTH_LEN + bpf_ntohs(len_be);
	}

	if (server_name_ext_off == 0) // Couldn't find server name extension.
		return 0;

	__u16 server_name_len_be;
	bpf_skb_load_bytes(skb,
			   server_name_ext_off + TLS_SERVER_NAME_LENGTH_OFF,
			   &server_name_len_be, 2);
	__u16 server_name_len = bpf_ntohs(server_name_len_be);
	if (server_name_len == 0 || server_name_len > TLS_MAX_SERVER_NAME_LEN)
		return 0;

	// The server name field under the server name extension.
	__u16 server_name_off = server_name_ext_off + TLS_SERVER_NAME_OFF;

	// Read the server name field.
	int counter = 0;
	for (int i = 0; i < TLS_MAX_SERVER_NAME_LEN; i++) {
		if (!out)
			break;
		if (i >= server_name_len)
			break;
		char b;
		bpf_skb_load_bytes(skb, server_name_off + i, &b, 1);
		if (b == '\0')
			break;
		out[i] = b;
		counter++;
	}
	return counter;
}

SEC("socket1")
int ig_trace_sni(struct __sk_buff *skb)
{
	// Skip frames with non-IP Ethernet protocol.
	struct ethhdr ethh;
	if (bpf_skb_load_bytes(skb, 0, &ethh, sizeof ethh))
		return 0;
	if (bpf_ntohs(ethh.h_proto) != ETH_P_IP)
		return 0;

	int ip_off = ETH_HLEN;
	// Read the IP header.
	struct iphdr iph;
	if (bpf_skb_load_bytes(skb, ip_off, &iph, sizeof iph))
		return 0;

	// Skip packets with IP protocol other than TCP.
	if (iph.protocol != IPPROTO_TCP)
		return 0;

	// An IPv4 header doesn't have a fixed size. The IHL field of a packet
	// represents the size of the IP header in 32-bit words, so we need to
	// multiply this value by 4 to get the header size in bytes.
	__u8 ip_header_len = iph.ihl * 4;
	int tcp_off = ip_off + ip_header_len;

	// Read the TCP header.
	struct tcphdr tcph;
	if (bpf_skb_load_bytes(skb, tcp_off, &tcph, sizeof tcph))
		return 0;

	if (!tcph.psh)
		return 0;

	// The data offset field in the header is specified in 32-bit words. We
	// have to multiply this value by 4 to get the TCP header length in bytes.
	__u8 tcp_header_len = tcph.doff * 4;
	// TLS data starts at this offset.
	int payload_off = tcp_off + tcp_header_len;

	// Parse SNI.
	char sni[TLS_MAX_SERVER_NAME_LEN] = {};
	int read = parse_sni(skb, payload_off, sni);
	if (read == 0)
		return 0;

	struct gadget_socket_value *skb_val = gadget_socket_lookup(skb);
	if (gadget_should_discard_data_by_skb(skb_val))
		return 0;

	struct event_t event = {
		0,
	};

	event.netns_id = skb->cb[0]; // cb[0] initialized by dispatcher.bpf.c
	for (int i = 0; i < TLS_MAX_SERVER_NAME_LEN; i++) {
		if (sni[i] == '\0')
			break;
		event.name[i] = sni[i];
	}
	event.timestamp_raw = bpf_ktime_get_boot_ns();

	// Enrich event with process metadata
	gadget_process_populate_from_socket(skb_val, &event.proc);

	gadget_output_buf(skb, &events, &event, sizeof(event));

	return 0;
}

char _license[] SEC("license") = "GPL";
