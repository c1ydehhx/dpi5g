from typing import Tuple

from bfrt_grpc.client import DataTuple

from core.switch_controller import Fec, SwitchController, Speed
from model.port_info import PortInfo
from model.data import Data
from utils.hex_converter import ip_to_hex, mac_to_hex


def switch_basic_init(switch: SwitchController, port_infos: Tuple[PortInfo]):
    # Add Port
    for port_info in port_infos:
        switch.add_port(port_info.dev_port, Speed.SPEED_10G, Fec.FEC_NONE)
        switch.enb_port(port_info.dev_port)

    # Add forward_table record
    for port_info in port_infos:
        switch.add_table_record(
            table_name="forward_table", 
            key_names=["hdr.ethernet.dstAddr"], 
            key_vals=[mac_to_hex(port_info.mac_address)], 
            action_name="forward",
            data_vals=[
                Data("port", port_info.dev_port)
            ]
        )
    
    # Add arp_forward_table record
    for port_info in port_infos:
        switch.add_table_record(
            table_name="arp_forward_table", 
            key_names=["hdr.arp.tpa"], 
            key_vals=[ip_to_hex(port_info.ip_address)], 
            action_name="arp_request_forward",
            data_vals=[
                Data("port", port_info.dev_port)
            ]
        )
