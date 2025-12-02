/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct gtpuhdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 version:3,
		protocol_type:1,
        reserved:1,
        is_next_header_exists:1,
        is_seq_number_present:1,
        is_n_pdu_present:1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8 is_n_pdu_present:1
        is_seq_number_present:1,
        is_next_header_exists:1,
        reserved:1,
		protocol_type:1,
        version:3;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
    __u8 message_type;
    __u16 length;
    __u32 teid;
    __u16 sequence;
    __u8 __no_used;
    __u8 pdu_session;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u32 extension_header_length:8,
        pdu_session_container:24;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u32 pdu_session_container:24,
        extension_header_length:8;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
};

struct simplifydnshdr {
    __u16 tx_id;
};

struct dns_query_key {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct dns_query_key);
    __type(value, __u16);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_allow_map SEC(".maps");

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx){
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct ethhdr *eth = data;
    int hdrsize = sizeof(*eth);
    
    if ((void*) eth + hdrsize > data_end){
        goto skip_packet;
    }

    struct iphdr *ipv4hdr = ((void*) eth + sizeof(*eth));

    if ((void*) ipv4hdr + sizeof(*ipv4hdr) > data_end){
        // bpf_printk("Debug: Is not IPv4 packet. Skip.\n");
        goto skip_packet;
    }

    struct udphdr *udphdr = ((void*) ipv4hdr + sizeof(*ipv4hdr));

    if ((void*) udphdr + sizeof(*udphdr) > data_end){
        // bpf_printk("Debug: Is not UDP packet. Skip.\n");
        goto skip_packet;
    }

    if (!(udphdr->source == bpf_ntohs(2152) && udphdr->dest == bpf_ntohs(2152))){
        // bpf_printk("Debug: Is not GTP-U UDP packet. source; %d, dest %d. Skip.\n", udphdr->source, udphdr->dest);
        goto skip_packet;
    }

    struct gtpuhdr *gtpuhdr = ((void*) udphdr + sizeof(*udphdr));

    if ((void*) gtpuhdr + sizeof(*gtpuhdr) > data_end){
        // bpf_printk("Debug: Is not GTP-U header packet. Skip.\n");
        goto skip_packet;
    }

    struct iphdr *second_ipv4_hdr = ((void*) gtpuhdr + sizeof(*gtpuhdr));

    if ((void*) second_ipv4_hdr + sizeof(*second_ipv4_hdr) > data_end){
        // bpf_printk("Debug: Is not 2nd-IPv4 header packet. Skip.\n");
        goto skip_packet;
    }


    if(second_ipv4_hdr->protocol != IPPROTO_UDP){
        // bpf_printk("Debug: 2nd-IPv4 is not UDP protocol (Protocol: %d). Skip.\n", second_ipv4_hdr->protocol);
        goto skip_packet;
    }

    struct udphdr *second_udp_hdr = ((void*) second_ipv4_hdr + sizeof(*second_ipv4_hdr));

    if((void*) second_udp_hdr + sizeof(*second_udp_hdr) > data_end){
        // bpf_printk("Debug: Is not 2nd-UDP header packet. Skip.\n");
        goto skip_packet;
    }

    if(second_udp_hdr->dest == bpf_ntohs(53)){
        struct simplifydnshdr *simplify_dns_hdr = ((void*) second_udp_hdr + sizeof(*second_udp_hdr));

        if((void*) simplify_dns_hdr + sizeof(*simplify_dns_hdr) > data_end){
            // bpf_printk("Debug: Transaction is not exists? Is abnormal DNS packet.");
            goto skip_packet;
        }

        struct dns_query_key query_key = {
            second_ipv4_hdr->saddr,
            second_ipv4_hdr->daddr,
            second_udp_hdr->source,
            second_udp_hdr->dest   
        };

        // unsigned char raw[12];
        // __builtin_memcpy(raw, &query_key, 12);

        // bpf_printk("dns_query_key RAW = %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
        //     raw[0], raw[1], raw[2], raw[3],
        //     raw[4], raw[5], raw[6], raw[7],
        //     raw[8], raw[9], raw[10], raw[11]);

        __u16* stored_txid = bpf_map_lookup_elem(&dns_allow_map, &query_key);

        if (!stored_txid){
            // bpf_printk("[Redirect] Key is not exists.");
        }

        if (stored_txid && *stored_txid != bpf_ntohs(simplify_dns_hdr->tx_id)){
            // bpf_printk("[Redirect] Key found but txID mismatch");
        }

        if(stored_txid && *stored_txid == bpf_ntohs(simplify_dns_hdr->tx_id)){
            bpf_map_delete_elem(&dns_allow_map, &query_key);
            return XDP_PASS;
        }else{
            // bpf_printk(
            //     "GTPU packet src=%x, inner UDP source port=%x, queue_index=%d, dns_txid=%d\n", 
            //     second_ipv4_hdr->saddr, 
            //     second_udp_hdr->source, 
            //     ctx->rx_queue_index, 
            //     bpf_ntohs(simplify_dns_hdr->tx_id)
            // );

            return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
        }
    }else{
        // bpf_printk("Debug: Is not 2nd-UDP DNS header packet. Skip.\n");
        goto skip_packet;
    }
skip_packet:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";