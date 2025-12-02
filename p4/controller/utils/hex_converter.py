def ip_to_hex(ip: str):
    ip_segment_strs = ip.split(".")
    result = 0

    for i in range(4):
        result |= (int(ip_segment_strs[i]) << (24 - i*8))
    
    return result


def mac_to_hex(mac: str):
    mac_segment_strs = mac.split(":")
    result = 0

    for i in range(6):
        result |= (int(mac_segment_strs[i], 16) << (40 - i*8))
    
    return result