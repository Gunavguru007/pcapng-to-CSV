import os
import pandas as pd
import pyshark
from tqdm import tqdm  # Progress bar for better visibility

# Define the directory to save the extracted CSV files
OUTPUT_DIR = r"C:\Users\gunav\Downloads\CSV"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def extract_pcap_to_csv(pcap_file):
    """Extracts relevant fields from a pcap file and saves to CSV."""
    output_csv = os.path.join(OUTPUT_DIR, os.path.basename(pcap_file).replace(".pcap", ".csv"))
    
    print(f"Processing {pcap_file}...")
    
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter="tcp || udp", timeout=10)
    except Exception as e:
        print(f"Error opening {pcap_file}: {e}")
        return
    
    data = []
    total_packets = 1000000  # Estimated large number for progress tracking
    packet_count = 0
    
    for packet in tqdm(capture, total=100, desc="Extracting packets", unit="pkt"):
        try:
            protocol = packet.highest_layer
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            length = packet.length
            timestamp = packet.sniff_time
            data.append([timestamp, src_ip, dst_ip, protocol, length])
            
            packet_count += 1
            if packet_count % (total_packets // 100) == 0:
                print(f"Progress: {packet_count // (total_packets // 100)}%")
                
            if packet_count >= total_packets:
                break
        except AttributeError:
            continue  # Skip packets with missing fields
        except Exception as e:
            print(f"Skipping corrupted packet: {e}")
            continue  # Avoid hanging on corrupt packets
    
    capture.close()
    
    if not data:
        print(f"No valid packets found in {pcap_file}")
        return
    
    df = pd.DataFrame(data, columns=["Timestamp", "Source IP", "Destination IP", "Protocol", "Length"])
    df.to_csv(output_csv, index=False)
    print(f"Extracted: {output_csv}")

if __name__ == "__main__":
    pcap_files = [
        "Wednesday-workingHours.pcap",
        "Tuesday-WorkingHours.pcap",
        "Monday-WorkingHours.pcap",
        "Friday-WorkingHours.pcap",
        "Thursday-WorkingHours.pcap"
    ]
    
    for pcap in pcap_files:
        extract_pcap_to_csv(pcap)
