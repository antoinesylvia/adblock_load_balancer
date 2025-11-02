import datetime
import os
import json
import requests
import threading
import logging
import time
import random
import socket
import struct
import traceback
from logging.handlers import RotatingFileHandler
from dnslib import DNSRecord

def read_constants_from_file(file_path):
    constants = {}
    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith('#'):
                key, value = line.split(':', 1)
                constants[key.strip()] = value.strip()
    return constants

constants = read_constants_from_file("load_balancer_config.txt")

# Extract the CONSTANT values from the config dictionary
ALLOWED_IPS_METRICS_SERVER = [ip.strip() for ip in constants.get('ALLOWED_IPS_METRICS_SERVER', '').split(",") if ip.strip()]  # List of allowed IP addresses for the metrics server
DISCORD_WEBHOOK_URL = constants.get('DISCORD_WEBHOOK_URL') # URL of your Discord webhook
LOG_FILE_BACKUP_COUNT = int(constants.get('LOG_FILE_BACKUP_COUNT', '0')) # Number of backups created
LOG_FILE_MAX_BYTES = int(constants.get('LOG_FILE_MAX_BYTES', '0')) # 20 MB
LOG_FILE_NAME = constants.get('LOG_FILE_NAME') # Name of log
METRICS_INTERVAL =  int(constants.get('METRICS_INTERVAL', '0'))  # Interval in seconds for collecting metrics
METRICS_URL = constants.get('METRICS_URL')
PI_HOLE_SERVERS = [server.strip() for server in constants.get('PI_HOLE_SERVERS', '').split(",") if server.strip()] # List of Pi-hole server IPs
UDP_BIND_ADDRESS = constants.get('UDP_BIND_ADDRESS') # URL for metrics server
UDP_BIND_PORT = int(constants.get('UDP_BIND_PORT', '0')) # Listening port for incoming DNS requests, be sure the port is open on your host firewall.


# Check if any required values are missing or have invalid data
missing_values = []
invalid_values = []

if not PI_HOLE_SERVERS:
    missing_values.append('PI_HOLE_SERVERS')
if LOG_FILE_NAME is None or LOG_FILE_NAME == "":
    missing_values.append('LOG_FILE_NAME')
if LOG_FILE_MAX_BYTES is None:
    invalid_values.append('LOG_FILE_MAX_BYTES')
elif not isinstance(LOG_FILE_MAX_BYTES, int):
    invalid_values.append('LOG_FILE_MAX_BYTES')
if LOG_FILE_BACKUP_COUNT is None:
    invalid_values.append('LOG_FILE_BACKUP_COUNT')
elif not isinstance(LOG_FILE_BACKUP_COUNT, int):
    invalid_values.append('LOG_FILE_BACKUP_COUNT')
if DISCORD_WEBHOOK_URL is None or DISCORD_WEBHOOK_URL == "":
    missing_values.append('DISCORD_WEBHOOK_URL')
if UDP_BIND_ADDRESS is None or UDP_BIND_ADDRESS == "":
    missing_values.append('UDP_BIND_ADDRESS')
if UDP_BIND_PORT is None:
    invalid_values.append('UDP_BIND_PORT')
elif not isinstance(UDP_BIND_PORT, int):
    invalid_values.append('UDP_BIND_PORT')
if METRICS_URL is None or METRICS_URL == "":
    missing_values.append('METRICS_URL')
if METRICS_INTERVAL is None:
    invalid_values.append('METRICS_INTERVAL')
elif not isinstance(METRICS_INTERVAL, int):
    invalid_values.append('METRICS_INTERVAL')
if not ALLOWED_IPS_METRICS_SERVER:
    missing_values.append('ALLOWED_IPS_METRICS_SERVER')

# Print error messages for missing or invalid values
if missing_values:
    print('Error: The following values are missing from the config data:', ', '.join(missing_values))
if invalid_values:
    print('Error: The following values have invalid data in the config data:', ', '.join(invalid_values))

# Lock for thread-safe access to server_metrics
metrics_lock = threading.Lock()

# Define server_metrics dictionary to store metrics
server_metrics = {}

# Function to send a Discord notification
def send_discord_notification():
    message = "PiHole forwarding application is down."
    payload = {
        "content": message
    }
    requests.post(DISCORD_WEBHOOK_URL, json=payload)

def is_valid_dns_request(data):
    # Verify that the data input is not empty or None
    if data is None or len(data) == 0:
        print("Invalid DNS request: Empty data")
        return False

    try:
        dns_header = struct.unpack('!HHHHHH', data[:12])
        _, _, _, _, _, question_count = dns_header

        if len(data) < 12 + question_count * 4:
            print(f"Invalid DNS request: Not enough bytes for DNS questions (Expected: {12 + question_count * 4}, Received: {len(data)})")
            return False

        try:
            dns_message = DNSRecord.parse(data)
        except Exception as e:
            print(f"Error parsing DNS request: {e}")
            return False

        # Print the contents of the binary data which represents a DNS request
        print("Binary Data:", data)

        # Mapping of numeric query types and query classes to their representations
        query_type_mapping = {
            1: "A (IPv4)",
            2: "NS (Name Server)",
            5: "CNAME (Canonical Name)",
            28: "AAAA (IPv6)",
            # Add more mappings as needed
        }

        query_class_mapping = {
            1: "IN (Internet)",
            2: "CS (CSNET class)",
            3: "CH (CHAOS class)",
            4: "HS (Hesiod class)",
            254: "NONE",
            255: "ANY",
            256: "FLUSH",
            258: "ZONEINIT",
            259: "ZONEREF",
            65535: "QCLASS_MASK",
            512: "CCHAOS",
            769: "HesIOD",
            890: "COPY",
            998: "Zone Management (ZM)",
            999: "UCLASS",
    # Add more mappings as needed
        }


        # Extract the domain name, query type, and query class from the DNS message
        if dns_message.questions:
            for question in dns_message.questions:
                domain = str(question.qname)
                query_type = query_type_mapping.get(question.qtype, str(question.qtype))
                query_class = query_class_mapping.get(question.qclass, str(question.qclass))

                # Print the translation of the binary data
                translation = f"Domain name: {domain} | Query type: {query_type} | Query Class: {query_class}"
                print("Binary Translation:", translation)
                print() 
        else:
            print("Invalid DNS request: No questions found")
            print() 
            return False

        # Validate the structure of the DNS request to ensure it conforms to the expected format
        # Check if the Query ID (QID) is valid
        qid = dns_message.header.id
        if not (0 <= qid <= 65535):
            print("Invalid DNS request: Invalid Query ID (QID)")
            return False

        # Additional validation checks specific to DNS question fields can be performed here

    except struct.error as se:
        if se.args and str(se).startswith("Error unpacking DNSQuestion"):
            error_message = str(se)
            print(f"Invalid DNS request: {error_message}")
            try:
                send_discord_notification()  # Send Discord notification
            except Exception as notification_error:
                print(f"Failed to send Discord notification: {str(notification_error)}")
            return False
        else:
            raise
    except Exception as e:
        print(f"Invalid DNS request: Unexpected error: {str(e)}")
        send_discord_notification()  # Send Discord notification
        return False

    # Return True if the validation passes, False otherwise
    return True

	
# The DNS server class definition
class DNSServer:
    def __init__(self, address, port):
        self.address = address
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.address, self.port))
        print(f"Listening on {self.address}:{self.port} (UDP)")
        self.last_consecutive_server = None
        self.fallback_mode = False

    # Method to start the DNS server
    def start(self):
        while True:
            try:
                data, addr = self.socket.recvfrom(4096)
                if self.fallback_mode:
                    self.handle_request_fallback(data, addr)
                else:
                    self.handle_request(data, addr)
            except ConnectionResetError:
                logging.error(f"Connection reset by peer {addr[0]}:{addr[1]}")
            except Exception as e:
                logging.error(f"Unhandled exception: {e}")
                break  # Exit the loop

    # Method to handle incoming DNS requests in normal mode
    def handle_request(self, data, addr):
        try:
            request = DNSRecord.parse(data)
            source_ip, _ = addr

            # Validate that the data input is not empty or None
            if data is None or len(data) == 0:
                logging.warning("Invalid DNS request: Empty data")
                return

            # Verify that there is at least one question in the DNS request
            if not request.questions:
                logging.warning("Invalid DNS request: No questions found")
                return

            # Get the domain name being queried
            domain = str(request.questions[0].qname)

            # Validate the DNS request structure
            if not is_valid_dns_request(data):
                logging.warning("Invalid DNS request. Discarding the request.")
                return

            # Get least loaded server among the non-consecutive servers
            non_consecutive_servers = [
                s for s in PI_HOLE_SERVERS if server_metrics.get(s) is not None and s != self.last_consecutive_server
            ]
            
            # Calculate load scores for debugging
            server_scores = {}
            for s in PI_HOLE_SERVERS:
                if server_metrics.get(s) is not None:
                    score = sum(value for value in server_metrics[s].values() if isinstance(value, (int, float)))
                    server_scores[s] = score
            
            logging.info(f"Server scores: {server_scores}, Last used: {self.last_consecutive_server}")
            
            if len(non_consecutive_servers) >= 1:
                server = min(
                    non_consecutive_servers,
                    key=lambda s: sum(
                        value for value in server_metrics[s].values() if isinstance(value, (int, float))
                    ),
                )
                logging.info(f"Selected {server} (score: {server_scores[server]}) from non-consecutive servers (avoiding {self.last_consecutive_server})")
            else:
                # Fall back to the default behavior of selecting the least loaded server
                available_servers = [s for s in PI_HOLE_SERVERS if server_metrics.get(s) is not None]
                server = min(
                    available_servers,
                    key=lambda s: sum(
                        value for value in server_metrics[s].values() if isinstance(value, (int, float))
                    ),
                    default=PI_HOLE_SERVERS[0],
                )
                logging.info(f"Selected {server} (score: {server_scores.get(server, 'N/A')}) from all available servers (no non-consecutive servers available)")

            # Send the DNS request to the selected server and receive the response
            response = self.forward_dns_query(request.pack(), server)

            # Check if the response is valid
            if response:
                # Append metrics if available for the selected server
                if server in server_metrics:
                    metrics = server_metrics[server]
                    log_message = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] Request from {source_ip} for ({domain}) forwarded to {server}:{UDP_BIND_PORT} (UDP) Metrics: {json.dumps(metrics)}"
                    logging.info(log_message)

                # Update the last consecutive server to avoid routing to same server next time
                self.last_consecutive_server = server

                self.socket.sendto(response, addr)

        except IndexError:
            # Handle the IndexError when list index is out of range
            logging.error("Invalid DNS request: No question found")
        except struct.error as se:
            if se.args and str(se).startswith("Error unpacking DNSQuestion"):
                error_message = str(se)
                logging.error(f"Invalid DNS request: {error_message}")
                try:
                    send_discord_notification()  # Send Discord notification
                except Exception as notification_error:
                    logging.error(f"Failed to send Discord notification: {str(notification_error)}")
            else:
                raise
        except Exception as e:
            logging.error(f"Unhandled exception: {e}")
            save_traceback()  # Save traceback to file for debugging


    # Method to handle incoming DNS requests in fallback mode
    def handle_request_fallback(self, data, addr):
        # Validate the DNS request structure
        if not is_valid_dns_request(data):
            logging.warning("Invalid DNS request. Discarding the request.")
            return

        request = DNSRecord.parse(data)
        domain = str(request.questions[0].qname)
        source_ip, _ = addr
        
        # Select a random server, but avoid selecting the same server consecutively
        available_servers = [s for s in PI_HOLE_SERVERS if s != self.last_consecutive_server]
        if available_servers:
            server = random.choice(available_servers)
        else:
            # If only one server or all servers were last used, just pick randomly
            server = random.choice(PI_HOLE_SERVERS)
        
        response = self.forward_dns_query(request.pack(), server)

        # Check if the response is valid
        if response:
            log_message = f"[{datetime.datetime.now()}] Request from {source_ip} for ({domain}) forwarded to {server}:{UDP_BIND_PORT} (UDP) [FALLBACK MODE]"
            logging.info(log_message)
            
            # Update last consecutive server to avoid routing to same server next time
            self.last_consecutive_server = server
            
            self.socket.sendto(response, addr)


    # Method to forward DNS queries to the selected DNS server
    def forward_dns_query(self, data, server):
        response = None
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            try:
                sock.sendto(data, (server, UDP_BIND_PORT))
                response, _ = sock.recvfrom(4096)
            except socket.timeout:
                logging.error(f"Timeout forwarding DNS query to {server} in fallback mode")
            except Exception as e:
                logging.error(f"Error forwarding DNS query to {server} in fallback mode: {e}")
        return response


ip_address_metrics = METRICS_URL.split('//')[1].split(':')[0]

# Function to receive metrics from the DNS servers via metrics code/server
def receive_metrics():
    consecutive_failures = 0
    last_logged_servers = set()  # Track which servers we've logged about

    while True:
        try:
            response = requests.get(METRICS_URL)
            if response.status_code == 200 and ip_address_metrics in ALLOWED_IPS_METRICS_SERVER:

                metrics = response.json()
                dns_server.fallback_mode = False  # Deactivate fallback mode
                consecutive_failures = 0

                # Only log if the set of servers has changed
                current_servers = set(metrics.keys())
                if current_servers != last_logged_servers:
                    logging.info(f"Received metrics from server: {list(metrics.keys())}")
                    logging.info(f"Expected PI_HOLE_SERVERS: {PI_HOLE_SERVERS}")
                    last_logged_servers = current_servers

                # Validate and update server metrics
                with metrics_lock:
                    for server in PI_HOLE_SERVERS:
                        if server in metrics:
                            if validate_metrics(metrics[server]):
                                server_metrics[server] = metrics[server]
                                logging.debug(f"Updated metrics for {server}")
                            else:
                                logging.warning(f"Invalid metrics received for {server}. Discarding the metrics.")
                        else:
                            logging.warning(f"No metrics received for {server} - server not in metrics response!")

            elif response.status_code != 200:
                consecutive_failures += 1
                if consecutive_failures >= 3:
                    logging.warning("Failed to retrieve metrics. Activating fallback mode.")
                    dns_server.fallback_mode = True
                    with metrics_lock:
                        server_metrics.clear()
                    consecutive_failures = 0
        except Exception as e:
            consecutive_failures += 1
            if consecutive_failures >= 3:
                logging.warning("Failed to retrieve metrics. Activating fallback mode.")
                dns_server.fallback_mode = True
                with metrics_lock:
                    server_metrics.clear()
                consecutive_failures = 0

        finally:
            if dns_server.fallback_mode:
                time.sleep(60)  # 1 minute in fallback mode between metrics URL checks
            else:
                time.sleep(METRICS_INTERVAL)

# Function to validate metrics data
def validate_metrics(metrics):
    # Check if the metrics dictionary has the expected keys
    expected_keys = ["server", "cpu_usage", "memory_usage", "load", "disk_usage"]
    if not all(key in metrics for key in expected_keys):
        return False

    # Validate individual metric values
    if not isinstance(metrics["server"], str):
        return False
    if not isinstance(metrics["cpu_usage"], (int, float)) or not (0 <= metrics["cpu_usage"] <= 100):
        return False
    if not isinstance(metrics["memory_usage"], (int, float)) or not (0 <= metrics["memory_usage"] <= 100):
        return False
    if not isinstance(metrics["load"], (int, float)):
        return False
    if not isinstance(metrics["disk_usage"], (int, float)) or not (0 <= metrics["disk_usage"] <= 100):
        return False

    # All validation checks passed
    return True


# Function to handle traceback and save to a file
def save_traceback():
    error_traceback = traceback.format_exc()
    with open("traceback.txt", "w") as file:
        file.write(error_traceback)


# Main entry point of the program
if __name__ == "__main__":
    try:
        # Create the log file if it doesn't exist
        if not os.path.exists(LOG_FILE_NAME):
            open(LOG_FILE_NAME, "w").close()

        # Create the DNS server instance
        dns_server = DNSServer(UDP_BIND_ADDRESS, UDP_BIND_PORT)

        # Define a custom logging formatter
        formatter = logging.Formatter("%(message)s")

        # Configure the log file handler with the custom formatter
        file_handler = RotatingFileHandler(LOG_FILE_NAME, maxBytes=LOG_FILE_MAX_BYTES, backupCount=LOG_FILE_BACKUP_COUNT)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)

        # Configure the console handler with the custom formatter
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)

        # Add the handlers to the logger
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)  # Set the root logger level
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        # Start the DNS server in a separate thread
        dns_thread = threading.Thread(target=dns_server.start)

        # Start receiving metrics in a separate thread
        metrics_thread = threading.Thread(target=receive_metrics)

        # Start the DNS server and metrics threads
        dns_thread.start()
        metrics_thread.start()

        # Wait for the threads to finish
        dns_thread.join()
        metrics_thread.join()

    except KeyboardInterrupt:
        # Keyboard interrupt received, terminate the program gracefully
        dns_server.socket.close()

    except Exception as e:
        # Save traceback to file
        save_traceback()
