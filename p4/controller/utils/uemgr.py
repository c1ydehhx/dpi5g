from utils.hex_converter import ip_to_hex
from utils.data_fetcher import fetch_ue_speed
from model.ue import UE

class UEMgr:
    def __init__(self):
        self.ue_data = {}
        
        for i in range(12):
            self.ue_data[ip_to_hex("10.10.216.33") + i] = {
                "ip": ip_to_hex("10.10.216.33") + i,
                "teid": None,
                "throughput": fetch_ue_speed(i),
                "device": "",
                "instance": ""
            }
    
    def register_ue_device_and_instance(self, hex_ip, device, instance):
        self.ue_data[hex_ip]["device"] = device
        self.ue_data[hex_ip]["instance"] = instance
            
    def register_ue_teid(self, hex_ip, teid):
        self.ue_data[hex_ip]["teid"] = teid
            
    def get_ue(self, hex_ip) -> UE:
        if self.ue_data[hex_ip]["teid"] == 0:
            raise RuntimeError("UE is not ready yet!")
        
        return UE(
            self.ue_data[hex_ip]["teid"],
            hex_ip,
            self.ue_data[hex_ip]["instance"],
            self.ue_data[hex_ip]["device"],
            self.ue_data[hex_ip]["throughput"],
        )