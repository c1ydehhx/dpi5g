from dataclasses import dataclass
from typing import Any, List

import pal_rpc.pal as pal_i
import conn_mgr_pd_rpc.conn_mgr as conn_mgr_client_module
import mc_pd_rpc.mc as mc_client_module
import bfruntime_pb2
from bfrt_grpc.client import BfruntimeReadWriteRpcException, ClientInterface, Target, KeyTuple, logger, logging, _Data, _Key
from enum import Enum
from pal_rpc.ttypes import pal_fec_type_t, pal_port_speed_t
from ptf.thriftutils import hex_to_i16
from res_pd_rpc.ttypes import DevTarget_t
from thrift.transport import TSocket, TTransport
from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol

from model.data import Data

logger.setLevel(logging.CRITICAL)

class Speed(Enum):
    SPEED_10G = pal_port_speed_t.BF_SPEED_10G
    SPEED_100G = pal_port_speed_t.BF_SPEED_100G


class Fec(Enum):
    FEC_NONE = pal_fec_type_t.BF_FEC_TYP_NONE
    FEC_FIRECODE = pal_fec_type_t.BF_FEC_TYP_FIRECODE
    FEC_REED_SOLOMON = pal_fec_type_t.BF_FEC_TYP_REED_SOLOMON


class SwitchController:
    def __init__(self, p4_name: str, host: str):
        self.connect(p4_name, host)
        
    def connect(self, p4_name: str, host: str):
        # print ("setting up gRPC client interface...")

        client_interface: ClientInterface = ClientInterface(f"{host}:{50052}", client_id=0, device_id=0)
        client_interface.bind_pipeline_config(p4_name)

        self.transport = TTransport.TBufferedTransport(TSocket.TSocket(host, 9090))
        self.transport.open()
        bprotocol = TBinaryProtocol.TBinaryProtocol(self.transport)

        self.pal = pal_i.Client(TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "pal"))
        self.conn_mgr = conn_mgr_client_module.Client(TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "conn_mgr"))
        self.mc = mc_client_module.Client(TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "mc"))

        self.sess_hdl = self.conn_mgr.client_init()
        self.mc_sess_hdl = self.mc.mc_create_session()  
        self.dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))

        self.p4_name = p4_name
        self.client_interface = client_interface


    def add_port(self, dev_port: int, speed: Speed, fec: Fec) -> None:
        # print(f"[PORT_ADD] Device Port {dev_port} / Speed {speed.name} / Fec {fec.name}")
        self.pal.pal_port_add(device=0, dev_port=dev_port, ps=speed.value, fec=fec.value)

    def enb_port(self, dev_port: int) -> None:
        # print(f"[PORT_ENB] Device Port {dev_port}")
        self.pal.pal_port_enable(device=0, dev_port=dev_port)

    def dis_port(self, dev_port: int) -> None:
        # print(f"[PORT_DIS] Device Port {dev_port}")
        self.pal.pal_port_dis(device=0, dev_port=dev_port)

    def del_port(self, dev_port: int) -> None:
        # print(f"[PORT_DEL] Device Port {dev_port}")
        self.pal.pal_port_del(device=0, dev_port=dev_port)

    def get_tables(self) -> list:
        bfrt_info = self.client_interface.bfrt_info_get(self.p4_name)
        return list(bfrt_info.table_dict.keys()); 
    
    def add_table_record(self, table_name: str, key_names: list, key_vals: list, data_vals: List[Data], action_name: str = None):
        print(f"[TABLE_ADD] Table Name {table_name} / Key Name {key_names} / Key Value {key_vals} / Action Name {action_name} / Data {data_vals}")
        bfrt_info = self.client_interface.bfrt_info_get(self.p4_name)
        target = Target(device_id=0, pipe_id=0xffff)
        table = bfrt_info.table_get(table_name) 
        key_list = [table.make_key([KeyTuple(key_name, key_val)]) for (key_name, key_val) in zip(key_names, key_vals)]
        bfrt_data_vals = [data_val.to_bfrt_data() for data_val in data_vals]

        if action_name is not None:
            data_list = [table.make_data(bfrt_data_vals, action_name)]
        else:
            data_list = [table.make_data(bfrt_data_vals)]
        
        table.entry_add(target, key_list, data_list)
            

    def modify_table_record(self, table_name: str, key_names: list, key_vals: list, data_vals: List[Data], action_name: str = None):
        print(f"[TABLE_MOD] Table Name {table_name} / Key Name {key_names} / Key Value {key_vals} / Action Name {action_name} / Data {data_vals}")
        bfrt_info = self.client_interface.bfrt_info_get(self.p4_name)
        target = Target(device_id=0, pipe_id=0xffff)
        table = bfrt_info.table_get(table_name)
        key_list = [table.make_key([KeyTuple(key_name, key_val)]) for (key_name, key_val) in zip(key_names, key_vals)]
        bfrt_data_vals = [data_val.to_bfrt_data() for data_val in data_vals]

        if action_name is not None:
            data_list = [table.make_data(bfrt_data_vals, action_name)]
        else:
            data_list = [table.make_data(bfrt_data_vals)]
        
        table.entry_mod(target, key_list, data_list)
    
    def get_register_val(self, register_name: str, key_names: list, key_vals: list):
        bfrt_info = self.client_interface.bfrt_info_get(self.p4_name)
        target = Target(device_id=0, pipe_id=0xffff)
        table = bfrt_info.table_get(register_name)
        key_list = [table.make_key([KeyTuple(key_name, key_val)]) for (key_name, key_val) in zip(key_names, key_vals)]

        raw_response_tuple: List = list(table.entry_get(target, key_list))[0]
        raw_data_list: _Data = raw_response_tuple[0]
        data_dict: dict = raw_data_list.to_dict()

        specific_key: str = ""

        for key in data_dict.keys():
            if "f1" in key:
                specific_key = key

        return data_dict[specific_key][0]