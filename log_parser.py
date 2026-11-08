def analyze_logs(log_file_path):
    """
    Parses a log file line-by-line using basic file handling loops 
    and checks for frequent authentication failures from individual IPs.
    """
    failed_attempts = {}
    ALERT_THRESHOLD = 5

    try:
        # GCSE File Handling: Open file in read-only mode safely
        with open(log_file_path, "r") as file:
            for line in file:
                # Identify if the entry details an authentication failure
                if "Failed password" in line:
                    # Simple text slicing to find the IP address safely
                    parts = line.split(" - ")
                    ip_part = parts[1] # e.g., "IP: 10.0.0.45"
                    ip_address = ip_part.replace("IP: ", "")
                    
                    # Track counts using a standard dictionary structure
                    if ip_address in failed_attempts:
                        failed_attempts[ip_address] += 1
                    else:
                        failed_attempts[ip_address] = 1

        # Defensive Monitoring Output
        print("-" * 60)
        print(" SECURITY ANALYSIS REPORT: AUTHENTICATION MONITORS")
        print("-" * 60)
        
        for ip, count in failed_attempts.items():
            if count >= ALERT_THRESHOLD:
                print(f"[!] INCIDENT RESPONSE ALERT: Potential Brute-Force Detected!")
                print(f"    Source IP Address: {ip}")
                print(f"    Total Failed Attempts: {count}")
                print(f"    Recommended Action: Block IP at Firewall Level.")
                print("-" * 60)
            else:
                print(f"[+] IP {ip}: {count} isolated failure(s). Normal baseline activity.")

    except FileNotFoundError:
        print(f"[-] Operational Error: Log file '{log_file_path}' could not be located.")

if _name_ == "_main_":
    # Point to the local mock log file
    analyze_logs("auth.log")
