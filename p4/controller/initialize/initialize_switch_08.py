from typing import List

import ptf.testutils as testutils
from bfrt_grpc.client import DataTuple

from core.switch_controller import Fec, SwitchController, Speed
from model.data import Data
from model.port_info import PortInfo
from utils.hex_converter import ip_to_hex, mac_to_hex

def init(switch: SwitchController, port_infos: List[PortInfo]):
    pass