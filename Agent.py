import psutil
import time
import socket
import json
import requests

def read_constants_from_file(file_path):
    constants = {}
    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith('#'):
                key, value = line.split(':', 1)
                constants[key.strip()] = value.strip()
    return constants

constants = read_constants_from_file("agent_config.txt")

METRICS_IP = constants.get('METRICS_IP') #IP of metrics server
METRICS_UDP_PORT = int(constants.get('METRICS_UDP_PORT', '0')) #UDP port for metrics server, make sure host has firewall rule to allow inbound requests on this port.
HEARTBEAT_URL = constants.get('HEARTBEAT_URL') #Address to send heartbeat signal via HTTP
HEARTBEAT_INTERVAL = int(constants.get('HEARTBEAT_INTERVAL', '0')) #How often to send heartbeat signal
ALLOWED_IP_ADDRESSES = [ip.strip() for ip in constants.get('ALLOWED_IP_ADDRESSES', '').split(",") if ip.strip()] # List of IPs allowed for outbound requests


# Check if any required values are missing or have invalid data
missing_values = []
invalid_values = []

# Check METRICS_IP
if METRICS_IP is None or METRICS_IP == "":
    missing_values.append('METRICS_IP')

# Check METRICS_UDP_PORT
if not isinstance(METRICS_UDP_PORT, int) or METRICS_UDP_PORT == 0:
    invalid_values.append('METRICS_UDP_PORT')

# Check HEARTBEAT_URL
if HEARTBEAT_URL is None or HEARTBEAT_URL == "":
    missing_values.append('HEARTBEAT_URL')

# Check HEARTBEAT_INTERVAL
if not isinstance(HEARTBEAT_INTERVAL, int) or HEARTBEAT_INTERVAL == 0:
    invalid_values.append('HEARTBEAT_INTERVAL')

# Check ALLOWED_IP_ADDRESSES
if not ALLOWED_IP_ADDRESSES:
    missing_values.append('ALLOWED_IP_ADDRESSES')

# Print error messages for missing or invalid values
if missing_values:
    print('Error: The following values are missing from the config data:', ', '.join(missing_values))
if invalid_values:
    print('Error: The following values have invalid data in the config data:', ', '.join(invalid_values))


# Get IP of network card on agent and send this as an identifier for the metrics being sent.
def get_main_nic_ip():
    try:
        if psutil.WINDOWS:
            return socket.gethostbyname(socket.gethostname())
        else:
            for name, info in psutil.net_if_addrs().items():
                for addr in info:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        return addr.address
    except Exception:
        return None

SERVER_IP = get_main_nic_ip()

# Collect system information to send
def get_metrics():
	cpu_usage = psutil.cpu_percent()
	memory_usage = psutil.virtual_memory().percent
	load = psutil.getloadavg()
	disk_usage = psutil.disk_usage('/').percent
	
	# Data Validation
	cpu_usage = max(min(cpu_usage, 100), 0)
	memory_usage = max(min(memory_usage, 100), 0)
	disk_usage = max(min(disk_usage, 100), 0)
    # Validate other metrics similarly
    
	metrics = {
        "server": SERVER_IP,
        "cpu_usage": cpu_usage,
        "memory_usage": memory_usage,
        "load": load[0],
        "disk_usage": disk_usage
	}
    
    # Input Filtering
	metrics_str = json.dumps(metrics)
	metrics_str = metrics_str.replace('<', '&lt;').replace('>', '&gt;')
    # Add any other necessary input filtering/escaping
    
	return metrics_str

last_heartbeat_time = time.time() - HEARTBEAT_INTERVAL  # Initial time to trigger heartbeat immediately

while True:
    try:
        current_time = time.time()

        # Send metrics
        metrics = get_metrics()
        print("Sending metrics:", metrics)

        if METRICS_IP in ALLOWED_IP_ADDRESSES:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(metrics.encode(), (METRICS_IP, METRICS_UDP_PORT))
            sock.close()
        else:
            print("Unauthorized IP. Metrics not sent.")

        # Send heartbeat once every hour
        if current_time - last_heartbeat_time >= HEARTBEAT_INTERVAL:
            if METRICS_IP in ALLOWED_IP_ADDRESSES:
                try:
                    response = requests.get(HEARTBEAT_URL, timeout=5)  # Set a timeout for the HTTP request
                    if response.status_code == 200:
                        print("Heartbeat signal sent successfully")
                        print("Successfully connected with the metrics server to send a heartbeat, next attempt in one minute.")
                    else:
                        print("Failed to send heartbeat signal. Status code:", response.status_code)
                        print("Failure to connect with the metrics server over HTTP. Will try again in one minute.")
                except requests.exceptions.RequestException as e:
                    exception_details = repr(e)
                    print("Heartbeat HTTP error:", exception_details)
                    print("Failure to connect with the metrics server over HTTP. Will try again in one minute.")
            else:
                print("Unauthorized IP. Heartbeat not sent.")

            last_heartbeat_time = current_time

        time.sleep(1)  # Wait 1 second before attempting again
    except socket.error as e:
        exception_details = repr(e)
        print("Agent UDP error:", exception_details)