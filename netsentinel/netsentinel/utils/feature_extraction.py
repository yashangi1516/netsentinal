import math
import time
import socket
import struct
from collections import Counter
from scapy.all import IP, TCP, UDP, ICMP

# Maintain state for inter-arrival time computation
_last_packet_time = None

def ip_to_int(ip_str):
    """Convert an IPv4 address string to a 32-bit integer representation."""
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except Exception:
        # Fallback for IPv6, names, or invalid formats
        return 0

def get_byte_entropy(payload):
    """Compute the Shannon entropy of the payload bytes (0 to 8)."""
    if not payload:
        return 0.0
    
    length = len(payload)
    counts = Counter(payload)
    entropy = 0.0
    
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def extract_features(packet):
    """
    Extracts a 10-dimensional numerical feature vector from a Scapy packet.
    
    Features:
    1. Packet size (bytes)
    2. Protocol (TCP=6, UDP=17, ICMP=1, ARP=2054, Other=0)
    3. Source IP (as integer)
    4. Destination IP (as integer)
    5. TTL (Time to Live)
    6. Flags (TCP flags representation, or 0)
    7. Source Port (or 0)
    8. Destination Port (or 0)
    9. Inter-arrival Time (seconds since last packet)
    10. Byte Entropy (0 to 8)
    
    Returns a dict with raw details and a list representing the feature vector.
    """
    global _last_packet_time
    
    # Current time
    curr_time = time.time()
    
    # 1. Packet Size
    size = len(packet)
    
    # Default values
    proto_num = 0
    src_ip_int = 0
    dst_ip_int = 0
    ttl = 0
    flags = 0
    src_port = 0
    dst_port = 0
    entropy = 0.0
    
    src_ip_str = "0.0.0.0"
    dst_ip_str = "0.0.0.0"
    proto_str = "OTHER"
    
    # Process IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        proto_num = ip_layer.proto
        src_ip_str = ip_layer.src
        dst_ip_str = ip_layer.dst
        src_ip_int = ip_to_int(src_ip_str)
        dst_ip_int = ip_to_int(dst_ip_str)
        ttl = ip_layer.ttl
        
        if proto_num == 6:
            proto_str = "TCP"
        elif proto_num == 17:
            proto_str = "UDP"
        elif proto_num == 1:
            proto_str = "ICMP"
            
    # Process Port numbers and TCP flags
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        # Convert TCP flags to numeric representation
        flags = int(tcp_layer.flags)
        # Payload entropy
        if tcp_layer.payload:
            entropy = get_byte_entropy(bytes(tcp_layer.payload))
            
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        src_port = udp_layer.sport
        dst_port = udp_layer.dport
        if udp_layer.payload:
            entropy = get_byte_entropy(bytes(udp_layer.payload))
            
    elif packet.haslayer(ICMP):
        # ICMP doesn't have ports, use type/code combined or 0
        src_port = 0
        dst_port = 0
        
    # Inter-arrival time
    if _last_packet_time is None:
        inter_arrival = 0.0
    else:
        inter_arrival = curr_time - _last_packet_time
    _last_packet_time = curr_time
    
    # Feature vector
    feature_vector = [
        float(size),
        float(proto_num),
        float(src_ip_int),
        float(dst_ip_int),
        float(ttl),
        float(flags),
        float(src_port),
        float(dst_port),
        float(inter_arrival),
        float(entropy)
    ]
    
    # Raw metadata dict for presentation and DB storage
    metadata = {
        "timestamp": curr_time,
        "size": size,
        "protocol": proto_str,
        "src_ip": src_ip_str,
        "dst_ip": dst_ip_str,
        "ttl": ttl,
        "flags": flags,
        "sport": src_port,
        "dport": dst_port,
        "inter_arrival": inter_arrival,
        "entropy": entropy
    }
    
    return metadata, feature_vector
