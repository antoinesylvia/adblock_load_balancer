import socket
import threading
import json
import logging
import requests
import os
import datetime
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from logging.handlers import RotatingFileHandler

def read_constants_from_file(file_path):
    constants = {}
    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith('#'):
                key, value = line.split(':', 1)
                constants[key.strip()] = value.strip()
    return constants

constants = read_constants_from_file("metrics_config.txt")

# Constants
AGENT_MAX_ALLOWED_DATA_SIZE = int(constants.get('AGENT_MAX_ALLOWED_DATA_SIZE', '0')) # Maximum allowed size of data from agent in bytes
ALLOWED_IPS_LOAD_BALANCERS = [ip.strip() for ip in constants.get('ALLOWED_IPS_LOAD_BALANCERS', '').split(",") if ip.strip()]#IP list of load balancers able to pull metrics
CONTENT_LENGTH_HEADER = constants.get('CONTENT_LENGTH_HEADER') # Size of the entity-body
CONTENT_TYPE_HEADER = constants.get('CONTENT_TYPE_HEADER') # Indicate the media type of the body sent to the recipient
DISCORD_WEBHOOK_URL = constants.get('DISCORD_WEBHOOK_URL') # URL of your Discord webhook
HEARTBEAT_ALERT_INTERVAL = int(constants.get('HEARTBEAT_ALERT_INTERVAL', '0')) # Time to wait before sending a notification to Discord that an agent is not reporting
HEARTBEAT_INTERVAL = int(constants.get('HEARTBEAT_INTERVAL', '0')) # Interval in seconds for heartbeat check
HEARTBEAT_LAST_NOTIFICATION_FILE = constants.get('HEARTBEAT_LAST_NOTIFICATION_FILE') # File to store the timestamp of the last notification
LOG_FILE_BACKUP_COUNT = int(constants.get('LOG_FILE_BACKUP_COUNT', '0')) # Number of backups created
LOG_FILE_MAX_BYTES = int(constants.get('LOG_FILE_MAX_BYTES', '0')) # 20 MB
LOG_FILE_NAME = constants.get('LOG_FILE_NAME') # Name of log
LOG_LEVEL = getattr(logging, constants.get('LOG_LEVEL', ''), logging.INFO) # Log level details
METRICS_SOCKET_ADDRESS_UDP_MAX_BIND_RETRIES = int(constants.get('METRICS_SOCKET_ADDRESS_UDP_MAX_BIND_RETRIES', '0')) # Maximum number of attempts to bind the UDP socket
METRICS_SERVER_ADDRESS_TCP = (constants.get('METRICS_SERVER_ADDRESS_TCP_IP'), int(constants.get('METRICS_SERVER_ADDRESS_TCP_PORT', '0'))) # Main load balancer code pulls from this address (IP of host running this code) via the HTTP server spun up in this code
METRICS_SOCKET_ADDRESS_UDP = (constants.get('METRICS_SOCKET_ADDRESS_UDP_IP'), int(constants.get('METRICS_SOCKET_ADDRESS_UDP_PORT', '0'))) # Agents send metrics to this address via UDP (the host IP running this code)
PI_HOLE_SERVERS = [server.strip() for server in constants.get('PI_HOLE_SERVERS', '').split(",") if server.strip()] # List of PiHole server IP addresses

# Check if any required values are missing or have invalid data
missing_values = []
invalid_values = []

# Check PI_HOLE_SERVERS
if not PI_HOLE_SERVERS:
    missing_values.append('PI_HOLE_SERVERS')

# Check LOG_FILE_NAME
if LOG_FILE_NAME is None or LOG_FILE_NAME == "":
    missing_values.append('LOG_FILE_NAME')

# Check LOG_FILE_MAX_BYTES
if LOG_FILE_MAX_BYTES is None:
    invalid_values.append('LOG_FILE_MAX_BYTES')
elif not isinstance(LOG_FILE_MAX_BYTES, int):
    invalid_values.append('LOG_FILE_MAX_BYTES')

# Check LOG_FILE_BACKUP_COUNT
if LOG_FILE_BACKUP_COUNT is None:
    invalid_values.append('LOG_FILE_BACKUP_COUNT')
elif not isinstance(LOG_FILE_BACKUP_COUNT, int):
    invalid_values.append('LOG_FILE_BACKUP_COUNT')

# Check DISCORD_WEBHOOK_URL
if DISCORD_WEBHOOK_URL is None or DISCORD_WEBHOOK_URL == "":
    missing_values.append('DISCORD_WEBHOOK_URL')

# Check METRICS_SOCKET_ADDRESS_UDP_IP
if METRICS_SOCKET_ADDRESS_UDP[0] is None or METRICS_SOCKET_ADDRESS_UDP[0] == "":
    missing_values.append('METRICS_SOCKET_ADDRESS_UDP_IP')

# Check METRICS_SOCKET_ADDRESS_UDP_PORT
if METRICS_SOCKET_ADDRESS_UDP[1] is None:
    invalid_values.append('METRICS_SOCKET_ADDRESS_UDP_PORT')
elif not isinstance(METRICS_SOCKET_ADDRESS_UDP[1], int):
    invalid_values.append('METRICS_SOCKET_ADDRESS_UDP_PORT')

# Check METRICS_SERVER_ADDRESS_TCP_IP
if METRICS_SERVER_ADDRESS_TCP[0] is None or METRICS_SERVER_ADDRESS_TCP[0] == "":
    missing_values.append('METRICS_SERVER_ADDRESS_TCP_IP')

# Check METRICS_SERVER_ADDRESS_TCP_PORT
if METRICS_SERVER_ADDRESS_TCP[1] is None:
    invalid_values.append('METRICS_SERVER_ADDRESS_TCP_PORT')
elif not isinstance(METRICS_SERVER_ADDRESS_TCP[1], int):
    invalid_values.append('METRICS_SERVER_ADDRESS_TCP_PORT')

# Check HEARTBEAT_INTERVAL
if HEARTBEAT_INTERVAL is None:
    invalid_values.append('HEARTBEAT_INTERVAL')
elif not isinstance(HEARTBEAT_INTERVAL, int):
    invalid_values.append('HEARTBEAT_INTERVAL')

# Check HEARTBEAT_ALERT_INTERVAL
if HEARTBEAT_ALERT_INTERVAL is None:
    invalid_values.append('HEARTBEAT_ALERT_INTERVAL')
elif not isinstance(HEARTBEAT_ALERT_INTERVAL, int):
    invalid_values.append('HEARTBEAT_ALERT_INTERVAL')

# Check METRICS_SOCKET_ADDRESS_UDP_MAX_BIND_RETRIES
if METRICS_SOCKET_ADDRESS_UDP_MAX_BIND_RETRIES is None:
    invalid_values.append('METRICS_SOCKET_ADDRESS_UDP_MAX_BIND_RETRIES')
elif not isinstance(METRICS_SOCKET_ADDRESS_UDP_MAX_BIND_RETRIES, int):
    invalid_values.append('METRICS_SOCKET_ADDRESS_UDP_MAX_BIND_RETRIES')

# Check HEARTBEAT_LAST_NOTIFICATION_FILE
if HEARTBEAT_LAST_NOTIFICATION_FILE is None or HEARTBEAT_LAST_NOTIFICATION_FILE == "":
    missing_values.append('HEARTBEAT_LAST_NOTIFICATION_FILE')

# Check AGENT_MAX_ALLOWED_DATA_SIZE
if AGENT_MAX_ALLOWED_DATA_SIZE is None:
    invalid_values.append('AGENT_MAX_ALLOWED_DATA_SIZE')
elif not isinstance(AGENT_MAX_ALLOWED_DATA_SIZE, int):
    invalid_values.append('AGENT_MAX_ALLOWED_DATA_SIZE')

# Check LOG_FILE_NAME
if LOG_FILE_NAME is None or LOG_FILE_NAME == "":
    missing_values.append('LOG_FILE_NAME')

# Check LOG_FILE_MAX_BYTES
if LOG_FILE_MAX_BYTES is None:
    invalid_values.append('LOG_FILE_MAX_BYTES')
elif not isinstance(LOG_FILE_MAX_BYTES, int):
    invalid_values.append('LOG_FILE_MAX_BYTES')

# Check LOG_FILE_BACKUP_COUNT
if LOG_FILE_BACKUP_COUNT is None:
    invalid_values.append('LOG_FILE_BACKUP_COUNT')
elif not isinstance(LOG_FILE_BACKUP_COUNT, int):
    invalid_values.append('LOG_FILE_BACKUP_COUNT')

# Check for missing or invalid values in ALLOWED_IPS_METRICS_SERVER
if not ALLOWED_IPS_LOAD_BALANCERS:
    missing_values.append('ALLOWED_IPS_LOAD_BALANCERS')

# Print error messages for missing or invalid values
if missing_values:
    print('Error: The following values are missing from the config data:', ', '.join(missing_values))
if invalid_values:
    print('Error: The following values have invalid data in the config data:', ', '.join(invalid_values))



# Initialize a lock for thread-safe access to server metrics
metrics_lock = threading.Lock()
# Initialize the server metrics
server_metrics = {server: None for server in PI_HOLE_SERVERS}
#Add allowed IPs for agents
allowed_ips_agents = PI_HOLE_SERVERS

# Configure logging for the metrics server.
def configure_logging(log_level):
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # Create a rotating file handler for log management
    file_handler = RotatingFileHandler(LOG_FILE_NAME, maxBytes=LOG_FILE_MAX_BYTES, backupCount=LOG_FILE_BACKUP_COUNT)

    file_handler.setLevel(log_level)

    # Create a stream handler to print logs to the CLI
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)

    # Create a formatter for the logs
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # Set the formatter for both handlers
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)

    # Add both handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)


# A decorator function to handle exceptions in request processing methods
def handle_request_exceptions(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except socket.error as e:
            logging.error(f"Socket error occurred: {e}")
            self.send_response(500)
            self.send_header(CONTENT_TYPE_HEADER, 'text/html')
            self.end_headers()
            self.wfile.write(b'Internal Server Error')
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP error occurred: {e}")
            self.send_response(500)
            self.send_header(CONTENT_TYPE_HEADER, 'text/html')
            self.end_headers()
            self.wfile.write(b'Internal Server Error')
        except Exception as e:
            logging.error(f"Exception occurred: {e}")
            self.send_response(500)
            self.send_header(CONTENT_TYPE_HEADER, 'text/html')
            self.end_headers()
            self.wfile.write(b'Internal Server Error')

    return wrapper


# Define a class to handle HTTP requests
class MetricsRequestHandler(BaseHTTPRequestHandler):
    # Check if the client IP address is allowed
    def is_ip_allowed_agents(self):
        client_ip = self.client_address[0]
        return client_ip in allowed_ips_agents
		
    # Check if the client IP address is allowed
    def is_ip_allowed_load_balancers(self):
        client_ip_1 = self.client_address[0]
        return client_ip_1 in ALLOWED_IPS_LOAD_BALANCERS

    # Handle POST requests for metrics from agents.
    @handle_request_exceptions
    def do_POST(self):
        if self.path == '/metrics':
            if not self.is_ip_allowed_load_balancers():
                self.send_response(403)
                self.send_header(CONTENT_TYPE_HEADER, 'text/html')
                self.end_headers()
                self.wfile.write(b'Forbidden')
            else:
                self.send_response(405)
                self.send_header(CONTENT_TYPE_HEADER, 'text/html')
                self.send_header('Allow', 'GET')
                self.end_headers()
                self.wfile.write(b'Method Not Allowed')
        elif self.path == '/heartbeat':
            if not self.is_ip_allowed_agents():
                self.send_response(403)
                self.send_header(CONTENT_TYPE_HEADER, 'text/html')
                self.end_headers()
                self.wfile.write(b'Forbidden')
            else:
                self.send_response(200)
                self.send_header(CONTENT_TYPE_HEADER, 'text/html')
                self.end_headers()
                self.wfile.write(b'Agent is alive.')
                logging.info(f'Received heartbeat signal from agent at "{self.client_address[0]}": {datetime.datetime.now()}')
                # Update the last notification time
                update_last_notification_time(self.client_address[0], datetime.datetime.now())

        else:
            self.send_response(400)
            self.send_header(CONTENT_TYPE_HEADER, 'text/html')
            self.end_headers()
            self.wfile.write(b'Bad Request')

    # Handle GET requests for grabbing metrics from the main code.
    @handle_request_exceptions
    def do_GET(self):
        if self.path == '/metrics':
            if not self.is_ip_allowed_load_balancers():
                self.send_response(403)
                self.send_header(CONTENT_TYPE_HEADER, 'text/html')
                self.end_headers()
                self.wfile.write(b'Forbidden')
            else:
                with metrics_lock:
                    content = json.dumps(server_metrics)
                self.send_response(200)
                self.send_header(CONTENT_TYPE_HEADER, 'application/json')
                self.end_headers()
                self.wfile.write(content.encode())
                # Update the last notification time
                update_last_notification_time(self.client_address[0], datetime.datetime.now())


        elif self.path == '/heartbeat':
            if not self.is_ip_allowed_agents():
                self.send_response(403)
                self.send_header(CONTENT_TYPE_HEADER, 'text/html')
                self.end_headers()
                self.wfile.write(b'Forbidden')
            else:
                self.send_response(200)
                self.send_header(CONTENT_TYPE_HEADER, 'text/html')
                self.end_headers()
                self.wfile.write(b'Agent is alive.')
                logging.info(f'Received heartbeat signal from agent at "{self.client_address[0]}": {datetime.datetime.now()}')
                # Update the last notification time
                update_last_notification_time(self.client_address[0], datetime.datetime.now())

        else:
            self.send_response(404)
            self.send_header(CONTENT_TYPE_HEADER, 'text/html')
            self.end_headers()
            self.wfile.write(b'Not found.')


# Create a UDP socket to receive metrics
def create_metrics_udp_socket():
    metrics_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bind_socket(metrics_socket)
    return metrics_socket


# Bind the UDP socket to an address
def bind_socket(metrics_socket, retry_interval=1, max_retries=METRICS_SOCKET_ADDRESS_UDP_MAX_BIND_RETRIES):
    retries = 0
    while retries < max_retries:
        try:
            metrics_socket.bind(METRICS_SOCKET_ADDRESS_UDP)
            break
        except socket.error as e:
            logging.error(f"Failed to create and bind the metrics UDP socket: {e}")
            # Sleep for a short time before retrying
            time.sleep(retry_interval)
            retries += 1
    else:
        logging.error("Maximum bind retries exceeded. Exiting.")


# Receive metrics from agents via UDP.
def receive_metrics(metrics_socket):
    while True:
        try:
            data, addr = metrics_socket.recvfrom(1024)  # Buffer size is 1024 bytes
            metrics_data = data.decode().strip()
            data_size = len(data)  # Get the size of the data in bytes

            # You could log or print this information
            logging.info(f"Received data of size from {addr[0]}: {data_size} bytes")

            # If you want to reject data that is too large, you can do that here:
            if data_size > AGENT_MAX_ALLOWED_DATA_SIZE:
                logging.warn(
                    f"Received data from {addr[0]} exceeded maximum allowed size of {AGENT_MAX_ALLOWED_DATA_SIZE} bytes")
                continue

            metrics = json.loads(metrics_data)
            server = metrics.get("server")
            if server:
                for key, value in metrics.items():
                    if isinstance(value, datetime.datetime):
                        metrics[key] = value.isoformat()  # Convert datetime to string

                # Validate metrics data
                if validate_metrics(metrics):
                    with metrics_lock:
                        server_metrics[server] = metrics
                    logging.info(f"Received valid metrics from {server}: {metrics_data}")
                else:
                    logging.error(f"Received invalid metrics from {server}: {metrics_data}")
            else:
                logging.error(f"Received invalid metrics: {metrics_data}")
        except socket.error as e:
            logging.error(f"Error occurred while receiving metrics: {e}")


# Validate the received metrics data
def validate_metrics(metrics):
    if not isinstance(metrics, dict):
        return False

    required_keys = {"server", "cpu_usage", "memory_usage", "load", "disk_usage"}
    if not required_keys.issubset(metrics.keys()):
        return False

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

    return True


# Send a Discord notification using the provided webhook URL.
def send_discord_notification(message):
    payload = {
        "content": message
    }
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
        if response.status_code == 200 or response.status_code == 204:
            logging.info("Discord notification sent successfully.")
            print("Discord notification sent successfully.")  # Print the success message to the CLI
        else:
            logging.error(f"Failed to send Discord notification. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send Discord notification: {e}")


# Get the last notification time from the file.
def get_last_notification_time():
    try:
        with open(HEARTBEAT_LAST_NOTIFICATION_FILE, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

# Update the last notification time in the file.
def update_last_notification_time(server, timestamp):
    data = {}

    try:
        with open(HEARTBEAT_LAST_NOTIFICATION_FILE, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    data[server] = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")

    try:
        with open(HEARTBEAT_LAST_NOTIFICATION_FILE, "w") as file:
            json.dump(data, file, indent=4)
            logging.info(f"Successfully updated last notification time: {server}: {timestamp}")
    except IOError as e:
        logging.error(f"Failed to update last notification time: {e}")







# Test Discord notification
#send_discord_notification("Testing Discord - Program Start")

def prepopulate_heartbeat_file():
    timestamps = {}

    for server in PI_HOLE_SERVERS:
        timestamps[server] = None

    with open(HEARTBEAT_LAST_NOTIFICATION_FILE, 'w') as f:
        json.dump(timestamps, f)

# Check the heartbeat of agents and send notifications if an agent hasn't reported for at least 10 minutes.
# Check the heartbeat of agents and send notifications if an agent hasn't reported for at least 10 minutes.
def check_heartbeat():
    last_notification_file = HEARTBEAT_LAST_NOTIFICATION_FILE

    # Pre-populate the heartbeat file if it doesn't exist
    prepopulate_heartbeat_file()

    # Load the last reported timestamps from the file
    agent_last_reported = get_last_notification_time()
    print(f"Loaded last reported timestamps: {agent_last_reported}")

    while True:
        current_time = datetime.datetime.now()  # Get the current time

        with metrics_lock:
            updated_agent_last_reported = {}

            for server in PI_HOLE_SERVERS:
                metrics = server_metrics.get(server)
                if metrics is not None and 'timestamp' in metrics:
                    last_reported = agent_last_reported.get(server)

                    if last_reported is None or last_reported != metrics['timestamp']:
                        last_reported = metrics['timestamp']

                    if (current_time - last_reported) > datetime.timedelta(seconds=HEARTBEAT_ALERT_INTERVAL):
                        send_discord_notification(f"The agent at {server} hasn't reported in the expected time frame.")
                        logging.info(f"Heartbeat alert sent for agent at {server}.")

                    updated_agent_last_reported[server] = last_reported

            # Update the last notification timestamps in the file
            agent_last_reported.update(updated_agent_last_reported)
            for server, timestamp in updated_agent_last_reported.items():
                agent_last_reported[server] = logging.Formatter("%Y-%m-%d %H:%M:%S.%f").format(timestamp)
            for server, timestamp in updated_agent_last_reported.items():
                update_last_notification_time(server, timestamp)

            print(f"Updated last reported timestamps: {agent_last_reported}")

        time.sleep(HEARTBEAT_INTERVAL)


# Main entry point of the program
if __name__ == "__main__":
    # Configure logging
    configure_logging(LOG_LEVEL)

    # Create metrics socket
    metrics_socket = create_metrics_udp_socket()

    # Start receiving metrics
    receive_metrics_thread = threading.Thread(target=receive_metrics, args=(metrics_socket,))
    receive_metrics_thread.start()

    # Start checking heartbeat
    heartbeat_thread = threading.Thread(target=check_heartbeat)
    heartbeat_thread.start()

    # Start the HTTP server
    server_address = METRICS_SERVER_ADDRESS_TCP
    http_server = HTTPServer(server_address, MetricsRequestHandler)
    logging.info(f"Metrics server running at http://{server_address[0]}:{server_address[1]}")

    # Create a thread for the HTTP server
    http_server_thread = threading.Thread(target=lambda: http_server.serve_forever())
    http_server_thread.start()

