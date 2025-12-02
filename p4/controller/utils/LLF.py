import random
from typing import Callable, Dict, List
from model.ue import UE
from model.upf import UPF
from utils.data_fetcher import UPFID
from utils.hex_converter import ip_to_hex

# LLF = Least Loading F-what(?)
class LLF:
    def __init__(self, upfs: List[UPF]):
        self.upfs = upfs
    
    def _find_ue_by_ip_addr(self, ues: List[UE], ip_addr: int):
        for ue in ues:
            if ue.get_ip_addr() == ip_addr:
                return ue
            
    def _find_upf_by_ip_addr(self, ip_addr: str):
        for upf in self.upfs:
            if upf.get_ip_addr() == ip_addr:
                return upf
            
    def _find_lowest_index_of_upf_loading_map(self, upf_loading_map: Dict[str, float]):
        min_loading = 9999
        min_upf_ip = self.upfs[0].get_ip_addr()
        
        for upf_ip, upf_loading in upf_loading_map.items():
            upf: UPF = self._find_upf_by_ip_addr(upf_ip)
            print(f"Check min {min_loading}, UPF loading {upf_loading}")
            if min_loading >= upf_loading:
                min_loading = upf_loading
                min_upf_ip = upf.get_ip_addr()
                
        return min_upf_ip
    
    def allow_swap_match_lowest_upfs(self, ues: List[UE]):
        upf_available_loading_temp: Dict[str, float] = dict([(upf.ip_addr, upf.max_loading_in_mbps - upf.background_loading_in_mbps) for upf in self.upfs])
        
        for ue in ues:
            ue_ip = ue.get_ip_addr()
            ue_binding_upf = ue.get_binding_upf()
            ue_sending_rate = ue.get_expected_bandwidth()
            
            if ue.get_binding_upf() == None:
                continue
            
            print(f"Loading information about allocated UE / UE IP {ue_ip} -> UPF IP {ue_binding_upf} / UE Sending Rate {ue_sending_rate} Mbps")
        
        key_func: Callable[[UE], int] = lambda u : u.get_expected_bandwidth()
        ues = sorted(ues, key=key_func, reverse=True)
        upfs = self.upfs.copy()
        
        random.shuffle(upfs)
        
        for ue in ues:
            ue.set_binding_upf(None)
            
            for upf in upfs:
                upf_ip = upf.get_ip_addr()
                if upf_available_loading_temp[upf_ip] >= ue.expected_bandwidth:
                    ue.set_binding_upf(upf_ip)
                    upf_available_loading_temp[upf_ip] -= ue.expected_bandwidth
                    break
            if ue.get_binding_upf() == None:
                maximal = 9999
                maximal_upf_space = upfs[0].get_ip_addr()
                for upf in upfs:
                    upf_ip = upf.get_ip_addr()
                    if maximal > upf_available_loading_temp[upf_ip]:
                        maximal = upf_available_loading_temp[upf_ip]
                        maximal_upf_space = upf_ip
                ue.set_binding_upf(maximal_upf_space)
                print(f"Assign UE IP {ue.get_ip_addr()} to {maximal_upf_space} / Expected Bandwidth of UE is {ue.get_expected_bandwidth()} / Outbound UPF bandwidth warning")
            else:
                print(f"Assign UE IP {ue.get_ip_addr()} to {upf_ip} / Expected Bandwidth of UE is {ue.get_expected_bandwidth()}")
                
        return ues
    
    def match_lowest_upfs(self, ues: List[UE]):
        upf_available_loading_temp: Dict[str, float] = dict([(upf.ip_addr, upf.max_loading_in_mbps - upf.background_loading_in_mbps) for upf in self.upfs])
        
        for ue in ues:
            ue_ip = ue.get_ip_addr()
            ue_binding_upf = ue.get_binding_upf()
            ue_sending_rate = ue.get_expected_bandwidth()
            
            if ue.get_binding_upf() == None:
                continue
            else:
                upf_available_loading_temp[ue.get_binding_upf()] -= ue.get_expected_bandwidth()
                print(f"Loading information about allocated UE / UE IP {ue_ip} -> UPF IP {ue_binding_upf} / UE Sending Rate {ue_sending_rate} Mbps")
            
        for upf_ip, sending_rate in upf_available_loading_temp.items():
            print(f"Now UPF {upf_ip} Backgound Loading {sending_rate}")
    
        for ue in ues:
            ue_ip = ue.get_ip_addr()
            if ue.get_binding_upf() == None:
                maximal = 0
                maximal_upf_space = self.upfs[0].get_ip_addr()
                for upf in self.upfs:
                    upf_ip = upf.get_ip_addr()
                    if maximal < upf_available_loading_temp[upf_ip]:
                        maximal = upf_available_loading_temp[upf_ip]
                        maximal_upf_space = upf_ip
                ue.set_binding_upf(maximal_upf_space)
                upf_available_loading_temp[ue.get_binding_upf()] -= ue.get_expected_bandwidth()
                print(f"Assign UE IP {ue.get_ip_addr()} to {maximal_upf_space} / Expected Bandwidth of UE is {ue.get_expected_bandwidth()}")
                
        
        return ues