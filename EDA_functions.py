import pandas as pd
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import io

def pcap_to_csv(uploaded_pcap):
    print("-------")

    # Try to read the PCAP file
    try:
        # Create a BytesIO object from the uploaded file's bytes
        pcap_bytes = io.BytesIO(uploaded_pcap.read())
        packets = rdpcap(pcap_bytes)
    except Exception as e:
        raise Exception(f"Error reading PCAP file: {str(e)}")

    data = []
    
    for packet in packets:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            ttl = packet[IP].ttl
            
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                seq = packet[TCP].seq
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                seq = None
            else:
                sport = None
                dport = None
                seq = None
            
            data.append({
                'IP Source': ip_src,
                'IP Destination': ip_dst,
                'Protocol': protocol,
                'TTL': ttl,
                'Source Port': sport,
                'Destination Port': dport,
                'Sequence Number': seq,
            })
    
    df = pd.DataFrame(data)
    return df