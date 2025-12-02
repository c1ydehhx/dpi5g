from enum import Enum
from utils.data_fetcher import fetch_ue_sending_rate

class UEStatus(Enum):
    DISCOVERED = 1
    UPDATED = 2


class UE:
    def __init__(self, teid, ip_addr, instance, device, expected_bandwidth):
        self.status = UEStatus.DISCOVERED
        self.teid = teid
        self.ip_addr = ip_addr
        self.instance = instance
        self.device = device
        self.binding_upf = None
        self.expected_bandwidth = expected_bandwidth

    def __eq__(self, value):
        return value.teid == self.teid and value.ip_addr == self.ip_addr

    def get_teid(self):
        return self.teid

    def get_ip_addr(self):
        return self.ip_addr
    
    def get_instance(self):
        return self.instance
    
    def get_device(self):
        return self.device
    
    def get_expected_bandwidth(self):
        return self.expected_bandwidth
    
    def get_sending_rate_in_mbps(self):
        return fetch_ue_sending_rate(self.instance, self.device) // 1e6

    def set_binding_upf(self, upf_ip):
        self.binding_upf = upf_ip
        
    def get_binding_upf(self):
        return self.binding_upf