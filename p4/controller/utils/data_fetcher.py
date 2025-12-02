import json
import pytz
from datetime import datetime
from enum import Enum
from requests import Response, get
from typing import List

class UPFID(Enum):
    UPF01 = 0
    UPF02 = 1
    UPF03 = 2
    UPF04 = 3

    
class Tunnel(Enum):
    N3 = 3
    N6 = 6


UPF_IPS: List[str] = [
    "192.168.132.48",
    "192.168.132.49",
    "192.168.132.61",
    "192.168.132.62"
]

UPF_N3_DEVICES: List[str] = [
    "enp2s0f1",
    "enp2s0f1",
    "enp2s0",
    "enp2s0",
]

UPF_N6_DEVICES: List[str] = [
    "enp2s0f0",
    "enp2s0f0",
    "enp3s0",
    "enp3s0",
]

def fetch_tunnel_load_in_bytes(upf: UPFID, tunnel: Tunnel):
    ip: str = UPF_IPS[upf.value]
    query_type: str = ""
    
    if tunnel == Tunnel.N3:
        device = UPF_N3_DEVICES[upf.value]
        query_type = "node_network_receive_bytes_total"
    else:
        device = UPF_N6_DEVICES[upf.value]
        query_type = "node_network_transmit_bytes_total"
        
    resp: Response = get("http://192.168.132.47:9090/api/v1/query", params= {
        "query": f'rate({query_type}{{device="{device}", instance="{ip}:9100"}}[1s])*8*1.07',
        "time": f'{int(datetime.now(pytz.timezone("Asia/Taipei")).timestamp())}'
    })
    
    resp_json = json.loads(resp.text)

    return float(resp_json["data"]["result"][0]["value"][1])

def fetch_ue_sending_rate(instance: str, device: str):
    resp: Response = get("http://192.168.132.47:9090/api/v1/query", params= {
        "query": f'rate(node_network_transmit_bytes_total{{instance="{instance}:9100", device="{device}"}}[1s])*8*1.07',
        "time": f'{int(datetime.now(pytz.timezone("Asia/Taipei")).timestamp())}'
    })
    
    resp_json = json.loads(resp.text)
    print(resp_json)

    if(len(resp_json["data"]["result"]) == 0):
        return 0

    return float(resp_json["data"]["result"][0]["value"][1])

def fetch_ue_speed(index: int):
    resp: Response = get(f"http://192.168.132.47:7789/ue-data/{index}")
    return int(resp.text)

def fetch_tunnel_load_in_percentage(upf: UPFID, tunnel: Tunnel) -> float:
    if(upf == UPFID.UPF01 or upf == UPFID.UPF02):
        # 10Gbps fiber -> divide 100000000 and get percentages
        return fetch_tunnel_load_in_bytes(upf, tunnel) / 100000000
    else:
        # 1Gbps RJ-45 -> divide 10000000 and get percentages
        return fetch_tunnel_load_in_bytes(upf, tunnel) / 10000000