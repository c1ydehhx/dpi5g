from dataclasses import dataclass

@dataclass
class PortInfo:
    dev_port: int
    ip_address: str = None
    mac_address: str = None