import json
from typing import Any

from requests import get

from utils.hex_converter import ip_to_hex

class RAN:
    def __init__(self, ip_addr: str):
        self.ip_addr = ip_addr
        self.up_ue_list = []

    def get_ip_addr(self):
        return self.ip_addr
    
    def get_up_ue_list(self):
        return self.up_ue_list
    
    def fetch_up_ues(self):
        resp = get(f"http://{self.ip_addr}:48763/")
        json_resp: dict[str, Any] = json.loads(resp.text)
        
        for key in json_resp.keys():
            if "uesimtun" in key:
                self.up_ue_list.append({
                    "device": key,
                    "ip": ip_to_hex(json_resp[key][0])
                })