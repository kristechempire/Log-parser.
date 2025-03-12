#!/usr/bin/python3

import sys
import re
from collections import Counter

# Regular expressions for extracting timestamps and IP addresses
TIMESTAMP_REGEX = r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b"  # Example: 2025-03-11 12:34:56
IP_REGEX = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"  # Matches IPv4 addresses

def parse_log(file_path):
    ip_counter = Counter()  # Count occurrences of each IP
    extracted_data = []  # Store extracted data

    try:
        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()
                
                # Extract timestamp
                timestamp_match = re.search(TIMESTAMP_REGEX, line)
                timestamp = timestamp_match.group() if timestamp_match else "No Timestamp"
                
                # Extract IP address
                ip_match = re.search(IP_REGEX, line)
                ip_address = ip_match.group() if ip_match else "No IP Found"
                
                # Count IP occurrence
                if ip_address != "No IP Found":
                    ip_counter[ip_address] += 1
                
                # Store extracted data
                extracted_data.append(f"{timestamp}, {ip_address}")

                print(f"Timestamp: {timestamp}, IP: {ip_address}, Log: {line}")

        # Save extracted data to a file
        with open("suspicious_ips.txt", "w") as output_file:
            output_file.write("\n".join(extracted_data))
        
        print("\n[+] Extracted data saved to suspicious_ips.txt")

        # Print IP address occurrences
        print("\n=== Suspicious IPs (Repeated Access) ===")
        for ip, count in ip_counter.items():
            if count > 1:
                print(f"IP: {ip} - {count} times")

    except FileNotFoundError:
        print("Log file not found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./log-parser.py <log_file>")
    else:
        parse_log(sys.argv[1])
