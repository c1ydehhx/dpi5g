from utils.data_fetcher import fetch_tunnel_load_in_bytes, Tunnel

class UPF:
    def __init__(self, upfid, mac_addr, ip_addr, output_port, background_loading_in_mbps, max_loading_in_mbps):
        self.upfid = upfid
        self.mac_addr = mac_addr
        self.ip_addr = ip_addr
        self.output_port = output_port
        self.max_loading_in_mbps = max_loading_in_mbps
        self.background_loading_in_mbps = background_loading_in_mbps
        
    def get_mac_addr(self):
        return self.mac_addr
    
    def get_ip_addr(self):
        return self.ip_addr
    
    def get_output_port(self):
        return self.output_port
    
    def get_N3_sending_rate_in_mbps(self) -> float:
        return fetch_tunnel_load_in_bytes(self.upfid, Tunnel.N3) // 1e6 - self.background_loading_in_mbps

    def get_N6_sending_rate_in_mbps(self) -> float:
        return fetch_tunnel_load_in_bytes(self.upfid, Tunnel.N6) // 1e6 - self.background_loading_in_mbps