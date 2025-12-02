// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header arp_t {
    bit<16> hrd; // Hardware Type
    bit<16> pro; // Protocol Type
    bit<8> hln; // Hardware Address Length
    bit<8> pln; // Protocol Address Length
    bit<16> op;  // Opcode
    bit<48> sha; // Sender Hardware Address
    bit<32> spa; // Sender Protocol Address
    bit<48> tha; // Target Hardware Address
    bit<32> tpa; // Target Protocol Address
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header gprs_t {
    bit<8> flags;
    bit<8> msgType;
    bit<16> len;
    bit<32> teid;
    bit<16> seq;
    bit<16> ext_type;
    bit<32> ext_payload;
}

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header ue_ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ue_udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct l2fwd_ingress_header_t {
    pktgen_timer_header_t timer;
    ethernet_t ethernet;
    arp_t arp;
    ipv4_t ipv4;
    tcp_t  tcp;
    udp_t  udp;
    gprs_t gprs; 
    ue_ipv4_t ue_ipv4;
    ue_udp_t ue_udp;
    icmp_t icmp;
}
struct l2fwd_ingress_metadata_t {
    bit<16> checksum_udp_tmp;
    bool checksum_upd_udp;
}
struct l2fwd_egress_header_t {}
struct l2fwd_egress_metadata_t {}

parser L2FWDIngressParser(
    packet_in pkt,
    out l2fwd_ingress_header_t hdr,
    out l2fwd_ingress_metadata_t metadata,
    out ingress_intrinsic_metadata_t ig_intr_md
) {
    Checksum() udp_checksum;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        
        pktgen_timer_header_t pktgen_pd_hdr = pkt.lookahead<pktgen_timer_header_t>();

        transition select(pktgen_pd_hdr.app_id) {
            1 : parse_pktgen_timer;
            2 : parse_pktgen_timer;
            default : parse_ethernet;
        }
    }

    state parse_pktgen_timer {
        pkt.extract(hdr.timer);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            0x0806: parse_arp;
            0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        udp_checksum.subtract({hdr.ipv4.dstAddr});
        udp_checksum.subtract({hdr.ipv4.srcAddr});
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            1: parse_icmp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        udp_checksum.subtract({hdr.udp.checksum});
        udp_checksum.subtract({hdr.udp.srcPort});
        metadata.checksum_udp_tmp = udp_checksum.get();
        transition select(hdr.udp.srcPort) {
            2152: parse_gprs;
            default: accept;
        }
    }

    state parse_gprs {
        pkt.extract(hdr.gprs);
        pkt.extract(hdr.ue_ipv4);
        transition select(hdr.ue_ipv4.protocol){
            17: parse_ue_udp;
            default: accept;
        }
    }

    state parse_ue_udp {
        pkt.extract(hdr.ue_udp);
        transition accept;
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }
}

parser L2FWDEgressParser(
    packet_in pkt,
    out l2fwd_egress_header_t hdr,
    out l2fwd_egress_metadata_t meta,
    out egress_intrinsic_metadata_t eg_intr_md
) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control L2FWDIngress(
    inout l2fwd_ingress_header_t hdr,
    inout l2fwd_ingress_metadata_t meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
    action arp_request_forward(PortId_t port){
        ig_tm_md.ucast_egress_port = port;
    }

    action forward(PortId_t port){
        ig_tm_md.ucast_egress_port = port;
    }

    action forward_specific_ue_udp_dst_port_packet(PortId_t port){
        ig_tm_md.ucast_egress_port = port;
    }

    action forward_valid_dns_packet_to_upf(PortId_t port, bit<48> srcAddr){
        hdr.ethernet.srcAddr = srcAddr;
        ig_tm_md.ucast_egress_port = port;
    }

    table arp_forward_table {
        key = {
            hdr.arp.tpa : exact;
        }
        actions = {
            arp_request_forward;
        }
        size = 1024;
    }

    table forward_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
        }
        size = 1024;
    }

    table forward_specific_ue_udp_dst_port_packet_table {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.ue_udp.dstPort: exact;
        }
        actions = {
            forward_specific_ue_udp_dst_port_packet;
        }
        size = 1024;
    }

    table forward_valid_dns_packet_to_upf_table {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            forward_valid_dns_packet_to_upf;
        }
        size = 1024;
    }

    apply {
        forward_valid_dns_packet_to_upf_table.apply();
        
        arp_forward_table.apply();
        forward_table.apply();

        if(ig_intr_md.ingress_port != 2) {
            forward_specific_ue_udp_dst_port_packet_table.apply();
        }
    }
}

control L2FWDEgress(
    inout l2fwd_egress_header_t hdr,
    inout l2fwd_egress_metadata_t meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md
) {
    apply {
        
    }
}

control L2FWDIngressDeparser(packet_out pkt,
    /* User */
    inout l2fwd_ingress_header_t hdr,
    in l2fwd_ingress_metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
) {
    Checksum() ipv4_checksum;
    Checksum() udp_checksum;

    apply {
        pkt.emit(hdr);
    }
}

control L2FWDEgressDeparser(
    packet_out pkt,
    inout l2fwd_egress_header_t hdr,
    in l2fwd_egress_metadata_t meta,
    in egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md
) {
    apply {
    }
}

Pipeline(
    L2FWDIngressParser(), L2FWDIngress(), L2FWDIngressDeparser(),
    L2FWDEgressParser(), L2FWDEgress(), L2FWDEgressDeparser()
) pipe;

Switch(pipe) main;
