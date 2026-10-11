import asyncio
import time
import random
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether

try:
    from ..utils.feature_extraction import extract_features, ip_to_int, get_byte_entropy
    from ..models.model_predict import ThreatDetector
    from .database import insert_packet, insert_anomaly, insert_alert, update_topology
except ImportError:
    from utils.feature_extraction import extract_features, ip_to_int, get_byte_entropy
    from models.model_predict import ThreatDetector
    from backend.database import insert_packet, insert_anomaly, insert_alert, update_topology

# Global thread-safe detector reference
detector = None
# Set to track active WebSocket broadcast callback
_broadcast_cb = None
capture_thread = None
running = False

# Simulated IPs
IP_POOL = [
    "192.168.1.10", "192.168.1.25", "192.168.1.50", "192.168.1.101", # Local LAN
    "10.0.0.5", "10.0.0.12",                                         # Internal Servers
    "8.8.8.8", "1.1.1.1",                                            # Public DNS
    "203.0.113.5", "198.51.100.22", "198.51.100.80"                 # Simulated External/Attacker IPs
]

def init_detector():
    global detector
    if detector is None:
        detector = ThreatDetector()

def get_anomaly_reason(threat_level, features, metadata):
    """Generates a descriptive reason for why the packet was classified as anomalous."""
    if threat_level == "Normal":
        return "Normal network activity."
    
    reasons = []
    # Index mapping:
    # 0: size, 1: proto, 5: flags, 7: dport, 8: inter_arrival, 9: entropy
    if features[0] > 1400:
        reasons.append("Unusually large packet size indicating potential bulk data transfer.")
    if features[5] == 2:  # SYN flag
        reasons.append("TCP SYN connection attempt.")
    if features[7] in [22, 23, 3389]:
        reasons.append(f"Attempted connection to sensitive port {metadata['dport']}.")
    if features[8] < 0.005:
        reasons.append("Extreme packet frequency / microsecond arrival interval.")
    if features[9] > 6.5:
        reasons.append("High byte payload entropy suggesting encrypted exfiltration or binary payloads.")
        
    if not reasons:
        reasons.append(f"Model detected variance in traffic baseline (anomaly level: {threat_level}).")
        
    return " & ".join(reasons)

async def process_packet(packet):
    """Extracts features, runs inference, saves to database, and broadcasts."""
    global _broadcast_cb
    try:
        metadata, features = extract_features(packet)
    except Exception as e:
        print(f"[Capture] Error extracting packet features: {e}")
        return
        
    # Run AI Inference
    if detector is None:
        init_detector()
        
    prediction = detector.predict(features)
    threat_level = prediction["threat_level"]
    
    # Merge prediction into packet metadata
    packet_info = {**metadata, **prediction}
    
    # Update topology
    await update_topology(metadata["src_ip"], metadata["dst_ip"], threat_level)
    
    # Database persistence
    await insert_packet(packet_info)
    
    if threat_level in ["Low", "Medium", "High"]:
        anomaly_reason = get_anomaly_reason(threat_level, features, metadata)
        alert_data = {
            "timestamp": metadata["timestamp"],
            "src_ip": metadata["src_ip"],
            "dst_ip": metadata["dst_ip"],
            "sport": metadata["sport"],
            "dport": metadata["dport"],
            "protocol": metadata["protocol"],
            "size": metadata["size"],
            "threat_level": threat_level,
            "threat_score": prediction["threat_score"],
            "anomaly_reason": anomaly_reason,
            "severity_color": prediction["severity_color"]
        }
        await insert_anomaly(packet_info)
        await insert_alert(alert_data)
        
        # Broadcast anomaly/alert if callback set
        if _broadcast_cb:
            asyncio.create_task(_broadcast_cb({"type": "alert", "data": alert_data}))
            
    # Broadcast raw packet info over WebSocket stream
    if _broadcast_cb:
        asyncio.create_task(_broadcast_cb({"type": "packet", "data": packet_info}))

def scapy_packet_handler(packet):
    """Synchronous callback for Scapy's sniff."""
    if not running:
        return
    # Use global loop to run the async process_packet method
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # Get standard event loop if not running
        loop = asyncio.get_event_loop()
        
    if loop.is_running():
        asyncio.run_coroutine_threadsafe(process_packet(packet), loop)
    else:
        # Fallback if loop isn't active yet
        asyncio.run(process_packet(packet))

def run_sniffing():
    """Start Scapy sniffing on a background thread."""
    print("[Capture] Starting Scapy packet sniffer on physical interface...")
    try:
        # Sniff on any interface, filtering IP traffic
        sniff(filter="ip", prn=scapy_packet_handler, store=0, stop_filter=lambda x: not running)
    except Exception as e:
        print(f"[Capture] Scapy sniffer failed: {e}. Switching to Simulated Traffic Engine.")
        asyncio.run(run_simulation())

async def run_simulation():
    """Generates simulated network packets and injects cyber threats."""
    print("[Capture] Simulated Traffic Engine started.")
    
    # Helper to generate Scapy-like IP/TCP packets programmatically
    def build_mock_packet(src, dst, proto, size, sport=0, dport=0, flags=0, payload_entropy=3.0):
        pkt = IP(src=src, dst=dst, proto=proto, ttl=64)
        if proto == 6: # TCP
            tcp_layer = TCP(sport=sport, dport=dport, flags=flags)
            if size > 40:
                # Add payload with entropy
                entropy_bytes = bytes([random.randint(0, 255) for _ in range(size - 40)]) if payload_entropy > 6.0 else b"A" * (size - 40)
                pkt = pkt/tcp_layer/entropy_bytes
            else:
                pkt = pkt/tcp_layer
        elif proto == 17: # UDP
            udp_layer = UDP(sport=sport, dport=dport)
            if size > 42:
                entropy_bytes = bytes([random.randint(0, 255) for _ in range(size - 42)]) if payload_entropy > 6.0 else b"B" * (size - 42)
                pkt = pkt/udp_layer/entropy_bytes
            else:
                pkt = pkt/udp_layer
        elif proto == 1: # ICMP
            pkt = pkt/ICMP()
        return pkt

    loop = asyncio.get_event_loop()
    
    while running:
        # Determine whether to generate normal traffic or inject an attack
        scenario = random.choices(["normal", "ddos", "port_scan", "exfiltration", "brute_force"], 
                                  weights=[0.85, 0.05, 0.04, 0.03, 0.03], k=1)[0]
                                  
        if scenario == "normal":
            # Normal HTTP/DNS/Standard transactions
            src = random.choice(IP_POOL[:4])  # Local client
            dst = random.choice(IP_POOL[4:])  # Server or external
            proto = random.choice([6, 17, 1])
            size = random.randint(64, 1000)
            sport = random.choice([80, 443, 53, 52021, 61002])
            dport = random.choice([80, 443, 53])
            flags = 16 if proto == 6 else 0  # ACK flag
            
            pkt = build_mock_packet(src, dst, proto, size, sport, dport, flags, payload_entropy=3.5)
            await process_packet(pkt)
            await asyncio.sleep(random.uniform(0.1, 0.8))
            
        elif scenario == "ddos":
            # DDoS Syn Flood (High volume SYN requests from a single external IP to local port 80)
            attacker = "203.0.113.5"
            victim = "192.168.1.50"
            print(f"[Attack Triggered] DDoS SYN Flood from {attacker} -> {victim}")
            
            # Send batch of packets rapidly
            for _ in range(30):
                sport = random.randint(49152, 65535)
                pkt = build_mock_packet(attacker, victim, 6, 64, sport, 80, flags=2) # SYN
                await process_packet(pkt)
                await asyncio.sleep(0.001)  # Microsecond inter-arrival
            await asyncio.sleep(2.0)
            
        elif scenario == "port_scan":
            # Port Scan (Sequential/random port scanning from an external IP)
            attacker = "198.51.100.22"
            victim = "192.168.1.25"
            print(f"[Attack Triggered] Port Scan from {attacker} -> {victim}")
            
            target_ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]
            for port in target_ports:
                sport = random.randint(30000, 40000)
                pkt = build_mock_packet(attacker, victim, 6, 60, sport, port, flags=2) # SYN scan
                await process_packet(pkt)
                await asyncio.sleep(0.05)
            await asyncio.sleep(2.0)
            
        elif scenario == "exfiltration":
            # Data Exfiltration (Large payloads, high entropy from internal host to external)
            source = "10.0.0.5"
            destination = "198.51.100.80"
            print(f"[Attack Triggered] Data Exfiltration from {source} -> {destination}")
            
            for _ in range(8):
                pkt = build_mock_packet(source, destination, 6, 1450, 49553, 443, flags=24, payload_entropy=7.8) # PSH+ACK high entropy
                await process_packet(pkt)
                await asyncio.sleep(0.1)
            await asyncio.sleep(2.0)
            
        elif scenario == "brute_force":
            # SSH/RDP Brute Force (Repeated connections to port 22/3389)
            attacker = "198.51.100.22"
            victim = "10.0.0.12"
            port = random.choice([22, 3389])
            print(f"[Attack Triggered] Brute Force on {victim}:{port} from {attacker}")
            
            for _ in range(12):
                sport = random.randint(49152, 65535)
                pkt = build_mock_packet(attacker, victim, 6, 80, sport, port, flags=24, payload_entropy=5.2)
                await process_packet(pkt)
                await asyncio.sleep(0.2)
            await asyncio.sleep(2.0)

def start_capture(broadcast_callback):
    """Initializes and runs the packet sniffing module."""
    global running, _broadcast_cb, capture_thread
    _broadcast_cb = broadcast_callback
    running = True
    
    init_detector()
    
    # Launch packet sniff/simulation
    capture_thread = threading.Thread(target=run_sniffing, daemon=True)
    capture_thread.start()
    print("[Capture] Packet sniffer thread started.")

def stop_capture():
    global running
    running = False
    print("[Capture] Packet sniffer stopped.")
