import re

# Define the log file path (modify this based on your system)
log_file_path = "/var/log/auth.log"  # Use "syslog" if "auth.log" is unavailable

# Define a function to parse the log file
def parse_log(file_path):
    try:
        with open(file_path, "r") as log_file:
            for line in log_file:
                if "Failed password" in line or "Invalid user" in line:
                    print(line.strip())  # Display failed login attempts
    except FileNotFoundError:
        print(f"Error: Log file '{file_path}' not found.")

# Run the parser
parse_log(log_file_path)
