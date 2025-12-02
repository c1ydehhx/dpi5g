from typing import List

import ptf.testutils as testutils

from core.switch_controller import Fec, SwitchController, Speed
from model.data import Data
from model.port_info import PortInfo
from utils.hex_converter import ip_to_hex, mac_to_hex

def init(switch: SwitchController, port_infos: List[PortInfo], recirculation_ports: List[PortInfo]):
    switch.add_table_record(
        table_name="forward_specific_udp_dst_port_packet_table", 
        key_names=["hdr.ipv4.srcAddr", "hdr.ipv4.dstAddr", "hdr.udp.dstPort"], 
        key_vals=[ip_to_hex("10.10.216.1"), ip_to_hex("10.10.216.2"), 2152], 
        action_name="forward_specific_ue_udp_dst_port_packet",
        data_vals=[
            Data("port", 10),
        ]
    )
    
    switch.add_table_record(
        table_name="forward_valid_dns_packet_to_upf_table", 
        key_names=["ig_intr_md.ingress_port"], 
        key_vals=[2], 
        action_name="forward_valid_dns_packet_to_upf",
        data_vals=[
            Data("port", 8),
            Data("srcAddr", mac_to_hex("90:e2:ba:c2:f1:da"))
        ]
    )