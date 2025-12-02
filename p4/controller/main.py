import time
from typing import List, Tuple

from bfrt_grpc.client import logger, logging

from initialize import initialize_switch_07_forward
from core.switch_controller import SwitchController
from model.port_info import PortInfo
from model.ue import UE, UEStatus
from model.upf import UPF
from model.ran import RAN
from model.data import Data
from switch_basic_init import switch_basic_init
from utils.hex_converter import mac_to_hex, ip_to_hex
from utils.data_fetcher import UPFID
from utils.LLF import LLF
from utils.uemgr import UEMgr

logger.setLevel(logging.CRITICAL)


def init_switch_07(switch: SwitchController):
    print("Initialize Switch 07")

    port_infos: tuple[PortInfo] = [
        PortInfo( 8, "10.10.216.2",  "90:e2:ba:c2:e5:8c"), # Port 34
        PortInfo(11, "10.12.216.1",  "90:e2:ba:c2:e5:8e"), # Port 35
        PortInfo(10, "10.10.216.101", "90:e2:ba:c2:f1:d8"), # Port 36
        PortInfo( 2, "10.11.216.102", "90:e2:ba:c2:f1:da"), # Port 37
        PortInfo( 0, "10.12.216.2", "90:e2:ba:c2:f3:96"), # Port 38
        PortInfo( 3, "10.10.216.1", "00:1b:21:bc:aa:3e"), # Port 39
    ]

    switch_basic_init(switch, port_infos)
    initialize_switch_07_forward.init(switch, port_infos, [])


def main():
    sw07 = SwitchController("l2fwd", "192.168.132.107")

    init_switch_07(sw07)

main()