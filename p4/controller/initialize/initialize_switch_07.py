from typing import List

import ptf.testutils as testutils

from core.switch_controller import Fec, SwitchController, Speed
from model.data import Data
from model.port_info import PortInfo
from utils.hex_converter import ip_to_hex, mac_to_hex

def init(switch: SwitchController, port_infos: List[PortInfo], recirculation_ports: List[PortInfo]):
    # Add Port
    for port_info in recirculation_ports:
        switch.add_port(port_info.dev_port, Speed.SPEED_10G, Fec.FEC_NONE)
        switch.enb_port(port_info.dev_port)

    # Add virtual_ip_arp_reply_table record
    switch.add_table_record(
        table_name="virtual_ip_arp_reply_table", 
        key_names=["hdr.arp.tpa"], 
        key_vals=[ip_to_hex("192.168.43.200")], 
        action_name="virtual_ip_arp_reply",
        data_vals=[
            Data("replySHA", mac_to_hex("00:1b:21:AA:BB:CC")),
            Data("replySPA", ip_to_hex("192.168.43.200"))
        ]
    )

    # Add virtual_ip_header_replacement_table record
    switch.add_table_record(
        table_name="virtual_ip_header_replacement_table", 
        key_names=["ig_intr_md.ingress_port", "hdr.ipv4.dstAddr"], 
        key_vals=[1, ip_to_hex("192.168.43.200")], 
        action_name="virtual_ip_ipv4_header_replacement",
        data_vals=[
            Data("dstMacAddr", mac_to_hex("90:e2:ba:c2:eb:fa")),
            Data("dstIPAddr", ip_to_hex("192.168.43.201")),
            Data("port", 9)
        ]
    )

    # Add multicast_ip_replacement_table record
    switch.add_table_record(
        table_name="multicast_ip_replacement_table", 
        key_names=["ig_intr_md.ingress_port"], 
        key_vals=[49], 
        action_name="handle_multicast_ip_modify",
        data_vals=[
            Data("dstMacAddr", mac_to_hex("90:e2:ba:c2:eb:fa")),
            Data("dstIPAddr", ip_to_hex("192.168.43.201")),
            Data("output_port", 9)
        ]
    )
    switch.add_table_record(
        table_name="multicast_ip_replacement_table", 
        key_names=["ig_intr_md.ingress_port"], 
        key_vals=[51], 
        action_name="handle_multicast_ip_modify",
        data_vals=[
            Data("dstMacAddr", mac_to_hex("90:e2:ba:c2:f6:76")),
            Data("dstIPAddr", ip_to_hex("192.168.43.202")),
            Data("output_port", 10)
        ]
    )
    switch.add_table_record(
        table_name="multicast_ip_replacement_table", 
        key_names=["ig_intr_md.ingress_port"], 
        key_vals=[32], 
        action_name="handle_multicast_ip_modify",
        data_vals=[
            Data("dstMacAddr", mac_to_hex("00:07:32:9c:69:b1")),
            Data("dstIPAddr", ip_to_hex("192.168.43.203")),
            Data("output_port", 131)
        ]
    )
    switch.add_table_record(
        table_name="multicast_ip_replacement_table", 
        key_names=["ig_intr_md.ingress_port"], 
        key_vals=[35], 
        action_name="handle_multicast_ip_modify",
        data_vals=[
            Data("dstMacAddr", mac_to_hex("00:07:32:9c:6a:01")),
            Data("dstIPAddr", ip_to_hex("192.168.43.204")),
            Data("output_port", 130)
        ]
    )

    # Add upf_source_ip_replacement_table record
    switch.add_table_record(
        table_name="upf_source_ip_replacement_table", 
        key_names=["hdr.ipv4.srcAddr"], 
        key_vals=[ip_to_hex("192.168.43.202")], 
        action_name="handle_upf_soruce_ip_to_virtual_ip",
        data_vals=[
            Data("srcMacAddr", mac_to_hex("00:1b:21:AA:BB:CC")),
            Data("srcIPAddr", ip_to_hex("192.168.43.200")),
        ]
    )

    # Configure PRE node
    switch.add_table_record(
        table_name="$pre.node", 
        key_names=["$MULTICAST_NODE_ID"], 
        key_vals=[1], 
        action_name=None,
        data_vals=[
            Data("$MULTICAST_RID", 5),
            Data("$MULTICAST_LAG_ID", int_arr_val=[]),
            Data("$DEV_PORT", int_arr_val=[48, 50, 33, 34])
        ]
    )

    # Configure PRE mgid
    switch.add_table_record(
        table_name="$pre.mgid", 
        key_names=["$MGID"], 
        key_vals=[1], 
        action_name=None,
        data_vals=[
            Data("$MULTICAST_NODE_ID", int_arr_val=[1]),
            Data("$MULTICAST_NODE_L1_XID_VALID", bool_arr_val=[0]),
            Data("$MULTICAST_NODE_L1_XID", int_arr_val=[0])
        ]
    )

    pipe_local_source_port = 0x44
    
    # Create a simple packet with 192.168.132.48/enp2s0f1 MAC address
    p = testutils.simple_ipv4ip_packet(
        eth_src="00:1b:06:AA:BB:CC", 
        eth_dst="90:e2:ba:c2:eb:fa", 
        ip_src="192.168.43.200", 
        ip_dst="192.168.43.201", 
        inner_frame=("0123456789"*100).encode()
    )
    
        # TF1 variables
    buffer_offset = 0
    pktlen = p.total_len
    b_count = 1
    p_count = 1
    
    # Configure t tables
    switch.add_table_record("t",
        key_names=["hdr.timer.pipe_id", "hdr.timer.app_id", "ig_intr_md.ingress_port"],
        key_vals=[0, 1, 0x44],
        action_name="match",
        data_vals=[
            Data("port", 9)
        ]
    )
    switch.add_table_record("t",
        key_names=["hdr.timer.pipe_id", "hdr.timer.app_id", "ig_intr_md.ingress_port"],
        key_vals=[0, 2, 0x44],
        action_name="match",
        data_vals=[
            Data("port", 10)
        ]
    )

    switch.add_table_record("tf1.pktgen.app_cfg", 
        key_names=["app_id"], 
        key_vals=[1], 
        action_name="trigger_timer_periodic", 
        data_vals=[
            Data('timer_nanosec', 920),
            Data('app_enable', bool_val=False),
            Data('pkt_len', pktlen - 6),
            Data('pkt_buffer_offset', buffer_offset),
            Data('pipe_local_source_port', pipe_local_source_port),
            Data('increment_source_port', bool_val=False),
            Data('batch_count_cfg', b_count - 1),
            Data('packets_per_batch_cfg', p_count - 1),
            Data('ibg', 0),
            Data('ibg_jitter', 0),
            Data('ipg', 0),
            Data('ipg_jitter', 0),
            Data('batch_counter', 0),
            Data('pkt_counter', 0),
            Data('trigger_counter', 0)
        ]
    )
    
    switch.add_table_record("tf1.pktgen.app_cfg", 
        key_names=["app_id"], 
        key_vals=[2], 
        action_name="trigger_timer_periodic", 
        data_vals=[
            Data('timer_nanosec', 920),
            Data('app_enable', bool_val=False),
            Data('pkt_len', pktlen - 6),
            Data('pkt_buffer_offset', buffer_offset),
            Data('pipe_local_source_port', pipe_local_source_port),
            Data('increment_source_port', bool_val=False),
            Data('batch_count_cfg', b_count - 1),
            Data('packets_per_batch_cfg', p_count - 1),
            Data('ibg', 0),
            Data('ibg_jitter', 0),
            Data('ipg', 0),
            Data('ipg_jitter', 0),
            Data('batch_counter', 0),
            Data('pkt_counter', 0),
            Data('trigger_counter', 0)
        ]
    )

    switch.add_table_record("tf1.pktgen.pkt_buffer", 
        key_names=["pkt_buffer_offset", "pkt_buffer_size"], 
        key_vals=[buffer_offset, pktlen - 6],
        data_vals=[
            Data("buffer", bytearray(bytes(p)[6:]))
        ]
    )

    switch.add_table_record("tf1.pktgen.port_cfg",
        key_names=["dev_port"],
        key_vals=[0x44],
        data_vals=[
            Data("pktgen_enable", bool_val=False)
        ]
    )

    # Start TF1 Generator
    switch.modify_table_record("tf1.pktgen.app_cfg", 
        key_names=["app_id"], 
        key_vals=[1], 
        action_name="trigger_timer_periodic",
        data_vals=[
            Data('app_enable', bool_val=False)
        ]
    )
    
    # Start TF1 Generator
    switch.modify_table_record("tf1.pktgen.app_cfg", 
        key_names=["app_id"], 
        key_vals=[2], 
        action_name="trigger_timer_periodic",
        data_vals=[
            Data('app_enable', bool_val=False)
        ]
    )

    # Create record for add report ue data port
    switch.add_table_record("record_ue_port_table", 
        key_names=["ig_intr_md.ingress_port"], 
        key_vals=[8], 
        action_name="record_available_ue_teid",
        data_vals=[]
    )

    switch.add_table_record("record_ue_port_table", 
        key_names=["ig_intr_md.ingress_port"], 
        key_vals=[11], 
        action_name="record_available_ue_teid",
        data_vals=[]
    )
    
    switch.add_table_record("record_ue_port_table", 
        key_names=["ig_intr_md.ingress_port"], 
        key_vals=[44], 
        action_name="record_available_ue_teid",
        data_vals=[]
    )
    
    switch.add_table_record("record_ue_port_table", 
        key_names=["ig_intr_md.ingress_port"], 
        key_vals=[2], 
        action_name="record_available_ue_teid",
        data_vals=[]
    )
