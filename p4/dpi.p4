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
    bit<8> ext_type;
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

struct l2fwd_ingress_header_t {
    pktgen_timer_header_t timer;
    ethernet_t ethernet;
    arp_t arp;
    ipv4_t ipv4;
    tcp_t  tcp;
    udp_t  udp;
    gprs_t gprs; 
    ue_ipv4_t ue_ipv4;
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

    // DirectRegister<bit<1>>() rr_value;
    // DirectRegisterAction<bit<1>, bit<1>> (rr_value) update_rr_value = {
    //     void apply(inout bit<1> reg_value){
    //         reg_value = ~reg_value;
    //     }
    // };
    Register<bit<32>, bit<32>>(1024) ue_ip_reg;

    action update_chksum(bool updated) {
        meta.checksum_upd_udp = updated;
    }

    action arp_request_forward(PortId_t port){
        ig_tm_md.ucast_egress_port = port;
    }

    action forward(PortId_t port){
        ig_tm_md.ucast_egress_port = port;
    }

    action virtual_ip_arp_reply(bit<48> replySHA, bit<32> replySPA){
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = replySHA;
        hdr.arp.spa = replySPA;
        hdr.arp.tpa = hdr.arp.spa;
        hdr.arp.tha = hdr.arp.sha;
        hdr.arp.sha = replySHA;
        hdr.arp.op = 2;

        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    action virtual_ip_ipv4_header_replacement(bit<48> dstMacAddr, bit<32> dstIPAddr, PortId_t port){
        ig_tm_md.ucast_egress_port = 0x1FF;
        ig_tm_md.mcast_grp_a = 1;
        ig_tm_md.rid = 1;
    }

    action handle_multicast_ip_modify(bit<48> dstMacAddr, bit<32> dstIPAddr, PortId_t output_port){
        hdr.ethernet.dstAddr = dstMacAddr;
        hdr.ipv4.dstAddr = dstIPAddr;

        ig_tm_md.ucast_egress_port = output_port;
    }

    action handle_multicast_traffic_gen(PortId_t output_port){
        ig_tm_md.ucast_egress_port = output_port;
    }

    action handle_upf_soruce_ip_to_virtual_ip(bit<48> srcMacAddr, bit<32> srcIPAddr) {
        hdr.ethernet.srcAddr = srcMacAddr;
        hdr.ipv4.srcAddr = srcIPAddr;
    }

    action record_available_ue_teid() {
        ue_ip_reg.write(hdr.gprs.teid, hdr.ue_ipv4.srcAddr);
    }

    action transmit_ue_packet_to_specific_port(bit<48> dstMacAddr, bit<32> dstIPAddr, PortId_t output_port){
        hdr.ethernet.dstAddr = dstMacAddr;
        hdr.ipv4.dstAddr = dstIPAddr;

        hdr.udp.checksum = 0;
        ig_tm_md.ucast_egress_port = output_port;
    }

    action forward_dns_packet_to_specific_port(PortId_t output_port){
        ig_tm_md.ucast_egress_port = output_port;
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

    table virtual_ip_arp_reply_table {
        key = {
            hdr.arp.tpa : exact;
        }
        actions = {
            virtual_ip_arp_reply;
        }
        size = 1024;
    }

    table virtual_ip_header_replacement_table {
        key = {
            ig_intr_md.ingress_port : exact;
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            virtual_ip_ipv4_header_replacement;
        }
        size = 1024;
    }

    table multicast_ip_replacement_table {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            handle_multicast_ip_modify;
        }
        size = 1024;
    }

    table upf_source_ip_replacement_table {
        key = {
            hdr.ipv4.srcAddr : exact;
        }
        actions = {
            handle_upf_soruce_ip_to_virtual_ip;
        }
        size = 1024;
    }

    table ue_packet_transmit_table {
        key = {
            hdr.gprs.teid : exact;
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            transmit_ue_packet_to_specific_port;
        }
        size = 1024;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;
    }

    action match(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table record_ue_port_table {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            record_available_ue_teid;
        }
        size = 1024;
    }

    table t {
        key = {
            hdr.timer.pipe_id : exact;
            hdr.timer.app_id  : exact;
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            match;
            @defaultonly drop;
        }
        const default_action = drop();
        size = 1024;
    }

    apply {
        multicast_ip_replacement_table.apply();

        if(hdr.gprs.isValid()){
            record_ue_port_table.apply();
        }
        ue_packet_transmit_table.apply();
        
        if(hdr.ipv4.protocol == 17){
            upf_source_ip_replacement_table.apply();
        }

        virtual_ip_header_replacement_table.apply();
        virtual_ip_arp_reply_table.apply();

        if (hdr.timer.isValid()) {
            t.apply();
        }

        update_chksum(true);

        if (hdr.udp.checksum == 0) {
            update_chksum(false);
        }

        arp_forward_table.apply();
        forward_table.apply();
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
