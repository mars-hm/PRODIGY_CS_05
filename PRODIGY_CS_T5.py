from scapy.all import sniff, IP
import pandas as pd
import os

packet_data = []

def packet_analyzer(packet):
    if IP in packet:
        ip_address = packet[IP]
        log_entry = {
            "Timestamp": pd.Timestamp.now(),
            "Source": ip_address.src,
            "Destination": ip_address.dst,
            "Protocol": ip_address.proto,
            "Payload": None  
        }
        
        packet_data.append(log_entry)

        print(log_entry)

def display():
    if not packet_data:
        print("No packet data captured.")
        return
    
    # Convert the packet data list to a DataFrame
    df = pd.DataFrame(packet_data)
    print("\nCaptured Packet Data:")
    print(df)  

def start():
    print("Network Packet Analyzer Initiated \nPress CTRL+C to Stop Execution.")
    try:
        sniff(prn=packet_analyzer, store=False)  
    except KeyboardInterrupt:
        display()
    except Exception as e:
        print(f"An error occurred: {e}")

start()
