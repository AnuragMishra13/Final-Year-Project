#!/usr/bin/env python3

import asyncio
import websockets
import json
import time
from scapy.all import *
from collections import defaultdict
import threading
import platform
import sys

# Feature lists in JSON format
FEATURE_CONFIG = {
    "DDoS": [
        "Flow Bytes/s",
        "Avg Packet Size",
        "Fwd Packets Length Total",
        "Packet Length Max",
        "Fwd Header Length",
        "Packet Length Min",
        "Fwd Act Data Packets",
        "Fwd IAT Max",
        "Flow IAT Min",
        "ACK Flag Count",
        "Avg Fwd Segment Size",
        "Init Fwd Win Bytes",
        "Fwd Packet Length Max",
        "Flow Duration",
        "Fwd Packets/s",
        "Flow IAT Max",
        "Fwd IAT Min",
        "Flow Packets/s",
        "Fwd IAT Total",
        "Bwd Packets/s",
        "URG Flag Count",
        "Bwd Packet Length Min",
        "Init Bwd Win Bytes",
        "Fwd Packet Length Min",
        "Down/Up Ratio",
        "Fwd Packet Length Mean",
        "Bwd IAT Max",
        "Bwd Packet Length Mean",
        "Bwd IAT Total",
        "Bwd Header Length",
        "Subflow Fwd Packets"
    ],
    "IDS": [
        "Flow Bytes/s",
        "Average Packet Size",
        "Total Length of Fwd Packets",
        "Fwd Packet Length Max",
        "Flow Duration",
        "Fwd Header Length",
        "Fwd Packets/s",
        "Min Packet Length",
        "Max Packet Length",
        "Fwd IAT Max",
        "Flow IAT Max",
        "Flow IAT Min",
        "Fwd IAT Min",
        "Fwd IAT Total",
        "Bwd Packets/s",
        "URG Flag Count",
        "ACK Flag Count",
        "Avg Fwd Segment Size",
        "Init_Win_bytes_forward",
        "Fwd Packet Length Min",
        "Down/Up Ratio",
        "Fwd Packet Length Mean",
        "Bwd IAT Max",
        "Bwd Packet Length Mean",
        "Bwd IAT Total",
        "Bwd Packet Length Min",
        "Bwd Header Length",
        "Subflow Fwd Packets",
        "Init_Win_bytes_backward",
        "act_data_pkt_fwd"
    ],
    "Src_ip": "Source_ip"
}

# Global variables for flow tracking
flows = defaultdict(lambda: {
    'packets': [],
    'start_time': None,
    'fwd_packets': [],
    'bwd_packets': [],
    'last_packet_time': None
})

capture_active = False
websocket_connection = None
main_event_loop = None
capture_interface = None
capture_lock = threading.Lock()  # Prevent race conditions

def get_windows_interface():
    """Get the best available network interface on Windows, prefer Wi-Fi by GUID or description"""
    try:
        interfaces = get_if_list()
        print(f"[*] Available interfaces: {interfaces}")

        # Try to get interface descriptions and GUIDs
        iface_descriptions = {}
        iface_guids = {}
        try:
            import wmi
            w = wmi.WMI()
            for nic in w.Win32_NetworkAdapter():
                if nic.NetConnectionID:
                    iface_descriptions[nic.NetConnectionID] = nic.Name
                    # Extract GUID from PNPDeviceID if possible
                    if hasattr(nic, 'GUID') and nic.GUID:
                        iface_guids[nic.NetConnectionID] = nic.GUID.lower()
        except Exception:
            pass

        # Filter out loopback and look for active interfaces
        active_interfaces = []
        for iface in interfaces:
            try:
                if 'loopback' in iface.lower() or 'lo' in iface.lower():
                    continue
                if_info = get_if_addr(iface)
                if if_info and if_info != '0.0.0.0':
                    active_interfaces.append(iface)
                    print(f"[*] Active interface found: {iface} ({if_info})")
            except:
                continue

        # 1. Prefer interface with GUID {C42CE835-ECD0-4648-93FE-FD8051B42ABD}
        preferred_guid = "{C42CE835-ECD0-4648-93FE-FD8051B42ABD}".lower()
        for iface in active_interfaces:
            if preferred_guid in iface.lower():
                print(f"[*] Selected Wi-Fi interface by GUID: {iface}")
                return iface

        # 2. Prefer interface with "wi-fi" or "wifi" in description (using WMI)
        preferred_keywords = ['wi-fi', 'wifi']
        for iface in active_interfaces:
            desc = iface_descriptions.get(iface, "").lower() if iface_descriptions else ""
            if any(pk in desc for pk in preferred_keywords):
                print(f"[*] Selected Wi-Fi interface by description: {iface}")
                return iface

        # 3. Fallback: Prefer Ethernet, avoid Bluetooth
        avoid_keywords = ['bluetooth']
        for iface in active_interfaces:
            iface_lower = iface.lower()
            desc = iface_descriptions.get(iface, "").lower() if iface_descriptions else ""
            if ('ethernet' in iface_lower or 'ethernet' in desc) and not any(ak in iface_lower or ak in desc for ak in avoid_keywords):
                print(f"[*] Selected Ethernet interface: {iface}")
                return iface

        # 4. Fallback: avoid Bluetooth
        for iface in active_interfaces:
            iface_lower = iface.lower()
            desc = iface_descriptions.get(iface, "").lower() if iface_descriptions else ""
            if not any(ak in iface_lower or ak in desc for ak in avoid_keywords):
                print(f"[*] Selected non-Bluetooth interface: {iface}")
                return iface

        # 5. If no preferred interface found, use the first active one
        if active_interfaces:
            selected = active_interfaces[0]
            print(f"[*] Selected interface: {selected}")
            return selected

        print("[!] No suitable interface found, using default")
        return None

    except Exception as e:
        print(f"[!] Error detecting interfaces: {e}")
        return None

def get_flow_key(packet):
    """Generate flow key from packet"""
    if IP in packet:
        if TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = packet[IP].proto
        elif UDP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = packet[IP].proto
        else:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = 0
            dst_port = 0
            protocol = packet[IP].proto

        # Create bidirectional flow key
        flow_tuple = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
        return f"{flow_tuple[0][0]}:{flow_tuple[0][1]}-{flow_tuple[1][0]}:{flow_tuple[1][1]}-{protocol}"
    return None

def extract_features(packet, flow_data):
    """Extract all required features from packet and flow data"""
    features = {}

    # Basic packet info
    packet_size = len(packet)
    packet_time = time.time()

    # Update flow data
    if flow_data['start_time'] is None:
        flow_data['start_time'] = packet_time

    flow_data['packets'].append({
        'size': packet_size,
        'time': packet_time,
        'packet': packet
    })

    # Determine packet direction (simplified)
    is_forward = True  # This would need more logic in real implementation

    if is_forward:
        flow_data['fwd_packets'].append({'size': packet_size, 'time': packet_time})
    else:
        flow_data['bwd_packets'].append({'size': packet_size, 'time': packet_time})

    # Calculate features
    total_packets = len(flow_data['packets'])
    fwd_packet_count = len(flow_data['fwd_packets'])
    bwd_packet_count = len(flow_data['bwd_packets'])

    # Flow duration
    flow_duration = packet_time - flow_data['start_time'] if flow_data['start_time'] else 0
    flow_duration = max(flow_duration, 0.000001)  # Avoid division by zero

    # Packet sizes
    packet_sizes = [p['size'] for p in flow_data['packets']]
    fwd_sizes = [p['size'] for p in flow_data['fwd_packets']]
    bwd_sizes = [p['size'] for p in flow_data['bwd_packets']]

    # Basic calculations
    total_bytes = sum(packet_sizes)
    fwd_total_bytes = sum(fwd_sizes)
    bwd_total_bytes = sum(bwd_sizes)

    # Inter-arrival times
    fwd_iats = []
    bwd_iats = []
    flow_iats = []

    if len(flow_data['fwd_packets']) > 1:
        for i in range(1, len(flow_data['fwd_packets'])):
            iat = flow_data['fwd_packets'][i]['time'] - flow_data['fwd_packets'][i-1]['time']
            fwd_iats.append(iat)

    if len(flow_data['bwd_packets']) > 1:
        for i in range(1, len(flow_data['bwd_packets'])):
            iat = flow_data['bwd_packets'][i]['time'] - flow_data['bwd_packets'][i-1]['time']
            bwd_iats.append(iat)

    if len(flow_data['packets']) > 1:
        for i in range(1, len(flow_data['packets'])):
            iat = flow_data['packets'][i]['time'] - flow_data['packets'][i-1]['time']
            flow_iats.append(iat)

    # Header lengths
    fwd_header_len = 0
    bwd_header_len = 0
    if IP in packet:
        ip_header_len = packet[IP].ihl * 4
        if TCP in packet:
            tcp_header_len = packet[TCP].dataofs * 4
            fwd_header_len = ip_header_len + tcp_header_len
            bwd_header_len = ip_header_len + tcp_header_len
        elif UDP in packet:
            fwd_header_len = ip_header_len + 8
            bwd_header_len = ip_header_len + 8

    # TCP flags
    ack_count = 0
    urg_count = 0
    if TCP in packet:
        if packet[TCP].flags & 0x10:  # ACK flag
            ack_count = 1
        if packet[TCP].flags & 0x20:  # URG flag
            urg_count = 1

    # Window sizes
    init_fwd_win = 0
    init_bwd_win = 0
    if TCP in packet and len(flow_data['packets']) == 1:
        init_fwd_win = packet[TCP].window

    # Calculate all features
    features = {
        "Flow Bytes/s": total_bytes / flow_duration if flow_duration > 0 else 0,
        "Average Packet Size": sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0,
        "Avg Packet Size": sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0,
        "Total Length of Fwd Packets": fwd_total_bytes,
        "Fwd Packets Length Total": fwd_total_bytes,
        "Max Packet Length": max(packet_sizes) if packet_sizes else 0,
        "Packet Length Max": max(packet_sizes) if packet_sizes else 0,
        "Min Packet Length": min(packet_sizes) if packet_sizes else 0,
        "Packet Length Min": min(packet_sizes) if packet_sizes else 0,
        "Fwd Packet Length Max": max(fwd_sizes) if fwd_sizes else 0,
        "Fwd Packet Length Min": min(fwd_sizes) if fwd_sizes else 0,
        "Fwd Packet Length Mean": sum(fwd_sizes) / len(fwd_sizes) if fwd_sizes else 0,
        "Bwd Packet Length Min": min(bwd_sizes) if bwd_sizes else 0,
        "Bwd Packet Length Mean": sum(bwd_sizes) / len(bwd_sizes) if bwd_sizes else 0,
        "Fwd Header Length": fwd_header_len,
        "Bwd Header Length": bwd_header_len,
        "Flow Duration": flow_duration,
        "Fwd Packets/s": fwd_packet_count / flow_duration if flow_duration > 0 else 0,
        "Bwd Packets/s": bwd_packet_count / flow_duration if flow_duration > 0 else 0,
        "Flow Packets/s": total_packets / flow_duration if flow_duration > 0 else 0,
        "Fwd IAT Max": max(fwd_iats) if fwd_iats else 0,
        "Fwd IAT Min": min(fwd_iats) if fwd_iats else 0,
        "Fwd IAT Total": sum(fwd_iats) if fwd_iats else 0,
        "Flow IAT Max": max(flow_iats) if flow_iats else 0,
        "Flow IAT Min": min(flow_iats) if flow_iats else 0,
        "Bwd IAT Max": max(bwd_iats) if bwd_iats else 0,
        "Bwd IAT Total": sum(bwd_iats) if bwd_iats else 0,
        "Fwd Act Data Packets": fwd_packet_count,
        "act_data_pkt_fwd": fwd_packet_count,
        "Subflow Fwd Packets": fwd_packet_count,
        "Init Fwd Win Bytes": init_fwd_win,
        "Init_Win_bytes_forward": init_fwd_win,
        "Init Bwd Win Bytes": init_bwd_win,
        "Init_Win_bytes_backward": init_bwd_win,
        "Down/Up Ratio": bwd_total_bytes / fwd_total_bytes if fwd_total_bytes > 0 else 0,
        "Avg Fwd Segment Size": fwd_total_bytes / fwd_packet_count if fwd_packet_count > 0 else 0,
        "ACK Flag Count": ack_count,
        "URG Flag Count": urg_count,
        "Source_ip": packet[IP].src if IP in packet else "unknown",
    }
    return features

def process_packet(packet):
    """Process captured packet and extract features"""
    global websocket_connection, main_event_loop

    # Filter: Only process packets sent from 192.168.1.11 (safety net)
    if IP in packet and packet[IP].src not in ["192.168.1.11", "192.168.1.2"]:
        return

    if not capture_active or not websocket_connection:
        return

    print("[*] Packet captured, processing...")

    flow_key = get_flow_key(packet)
    if not flow_key:
        print("[!] Could not generate flow key for packet")
        return

    # Extract features
    features = extract_features(packet, flows[flow_key])
    print("[*] Features extracted")

    # Create feature vectors in required order
    ddos_features = []
    ids_features = []

    for feature_name in FEATURE_CONFIG["DDoS"]:
        ddos_features.append(features.get(feature_name, 0))

    for feature_name in FEATURE_CONFIG["IDS"]:
        ids_features.append(features.get(feature_name, 0))

    # Format as required JSON
    result = {
        "DDoS": ddos_features,
        "IDS": ids_features,
        "Src_ip": features.get("Source_ip", "unknown")
    }

    print("[*] Sending features to WebSocket...")

    # Send to WebSocket using the main event loop from the thread
    if main_event_loop:
        asyncio.run_coroutine_threadsafe(send_features(result), main_event_loop)
    else:
        print("[!] No main event loop available to send features")

async def send_features(features):
    """Send features to WebSocket server"""
    global websocket_connection
    try:
        if websocket_connection:
            await websocket_connection.send(json.dumps(features))
            print(f"[+] Sent features: DDoS={len(features['DDoS'])} features, IDS={len(features['IDS'])} features")
    except Exception as e:
        print(f"[!] Error sending features: {e}")

def start_packet_capture():
    """Start capturing packets on Windows"""
    global capture_active, capture_interface
    with capture_lock:
        if capture_active:
            return
        capture_active = True

    # Get the best interface for Windows
    if capture_interface is None:
        capture_interface = get_windows_interface()

    if capture_interface:
        print(f"[*] Starting packet capture on interface '{capture_interface}'...")
    else:
        print("[*] Starting packet capture on default interface...")

    def capture_loop():
        try:
            print("[*] Waiting for packet...")

            # Only process packets with source IP 192.168.1.11 or 192.168.1.2
            def ip_filter(pkt):
                return IP in pkt and pkt[IP].src in ["192.168.1.11", "192.168.1.2"]

            # Use different parameters for Windows
            if capture_interface:
                # Capture with specific interface
                sniff(iface=capture_interface, prn=process_packet, lfilter=ip_filter, count=1, timeout=2, store=0)
            else:
                # Capture on default interface
                sniff(prn=process_packet, lfilter=ip_filter, count=1, timeout=2, store=0)

            print("[*] Packet processed...")

            if capture_active:
                # Schedule next packet capture with shorter interval
                threading.Timer(0.5, capture_loop).start()

        except PermissionError:
            print("[!] Permission denied. Please run as Administrator on Windows.")
            if capture_active:
                threading.Timer(2.0, capture_loop).start()
        except Exception as e:
            print(f"[!] Capture error: {e}")
            if capture_active:
                threading.Timer(1.0, capture_loop).start()

    capture_loop()

def stop_packet_capture():
    """Stop capturing packets"""
    global capture_active
    with capture_lock:
        capture_active = False
    print("[*] Stopped packet capture")

# Windows-specific event loop policy
def set_windows_event_loop_policy():
    if platform.system() == 'Windows':
        # Set the event loop policy to prevent issues on Windows
        if sys.version_info >= (3, 8):
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

async def handle_websocket():
    """Handle WebSocket connection and messages"""
    global websocket_connection, capture_active

    uri = "ws://127.0.0.1:8765"

    try:
        async with websockets.connect(uri) as websocket:
            websocket_connection = websocket
            print(f"Connected to WebSocket server at {uri}")

            async for message in websocket:
                print(f"Received message: {message}")
                # Accept both plain string and JSON message
                try:
                    msg_obj = json.loads(message)
                    msg = msg_obj.get("message", "").strip().lower()
                except Exception:
                    msg = message.strip().lower()
                if msg == "start packet capture":
                    if not capture_active:
                        threading.Thread(target=start_packet_capture, daemon=True).start()
                elif msg == "stop packet capture":
                    stop_packet_capture()

    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        websocket_connection = None
        stop_packet_capture()

async def main():
    """Main function"""
    global main_event_loop

    # Set Windows-specific event loop policy
    set_windows_event_loop_policy()

    main_event_loop = asyncio.get_running_loop()
    print("Windows Packet Capture API starting...")
    print(f"Running on {platform.system()} {platform.release()}")

    # Check if running as administrator on Windows
    if platform.system() == 'Windows':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] Warning: Not running as Administrator. Packet capture may fail.")
                print("[!] Please run as Administrator for best results.")
        except:
            pass

    print("Waiting for WebSocket connection...")

    while True:
        try:
            await handle_websocket()
        except Exception as e:
            print(f"Connection failed: {e}")
            print("Retrying in 5 seconds...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down...")
        stop_packet_capture()
    except Exception as e:
        print(f"Error: {e}")
        input("Press Enter to exit...")
