import sys
import os
import time
import json
import threading
import signal
import subprocess
import re
import numpy as np
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
import requests
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout,
                             QGridLayout, QLineEdit, QPushButton, QLabel, QComboBox, QTextEdit,
                             QFileDialog, QWidget)
from PyQt5.QtCore import Qt
import logging
from logging.handlers import RotatingFileHandler
import getpass

# Constants
TIMEOUT_SECONDS = 3600
MAX_TRAINING_SAMPLES = 1000
LEARNING_RATE = 0.01
EPOCHS = 500
THREAT_THRESHOLD = 0.7
PACKET_RATE_THRESHOLD = 100.0
CONNECTION_THRESHOLD = 50
AVERAGE_PACKET_SIZE = 512
PACKET_SIZE_MULTIPLIER = 5
MAINTENANCE_INTERVAL_MS = 3600000
THREAT_CHECK_INTERVAL_MS = 10000
LOG_ROTATION_SIZE = 10485760
DROPOUT_RATE = 0.2
BATCH_SIZE = 32
MODEL_FILE = "neural_model.json"
CONFIG_FILE = "yuna_config.json"
BLOCKED_IPS_FILE = "blocked_ips.json"
BLOCKED_DOMAINS_FILE = "blocked_domains.json"
THREAT_INTEL_API = "https://api.threatintel.example.com/query"
GEOIP_RATE_LIMIT_SECONDS = 1.5

# Global variables
running = True
blocked_ips = set()
blocked_domains = {}
global_mutex = threading.Lock()

# Signal handler
def signal_handler(sig, frame):
    """Handle interrupt signal for graceful shutdown."""
    global running
    logger.info("Interrupt signal received. Shutting down gracefully...")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Logger setup
class Logger:
    @staticmethod
    def setup():
        """Configure logging with rotating file handler."""
        log_dir = os.path.expanduser("~/FirewallManagerLogs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, "firewall_manager.log")
        
        logger = logging.getLogger('YUNAFirewall')
        logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(log_file, maxBytes=LOG_ROTATION_SIZE, backupCount=1)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

logger = Logger.setup()

# Neural Network
class NeuralNetwork:
    """Neural network for threat detection."""
    def __init__(self, input_size=4, hidden_size1=8, hidden_size2=4, output_size=1):
        self.input_size = input_size
        self.hidden_size1 = hidden_size1
        self.hidden_size2 = hidden_size2
        self.output_size = output_size
        
        # Initialize weights and biases
        np.random.seed(42)
        self.weights_ih1 = np.random.uniform(-0.5, 0.5, (input_size, hidden_size1))
        self.weights_h1h2 = np.random.uniform(-0.5, 0.5, (hidden_size1, hidden_size2))
        self.weights_h2o = np.random.uniform(-0.5, 0.5, (hidden_size2, output_size))
        self.bias_h1 = np.random.uniform(-0.5, 0.5, (hidden_size1,))
        self.bias_h2 = np.random.uniform(-0.5, 0.5, (hidden_size2,))
        self.bias_o = np.random.uniform(-0.5, 0.5, (output_size,))
        self.output = np.zeros(output_size)

    def sigmoid(self, x):
        """Apply sigmoid activation function."""
        return 1.0 / (1.0 + np.exp(-np.clip(x, -500, 500)))

    def sigmoid_derivative(self, x):
        """Compute derivative of sigmoid function."""
        return x * (1.0 - x)

    def forward_propagate(self, inputs, dropout_rate=0.0):
        """Perform forward propagation through the network."""
        if not isinstance(inputs, np.ndarray) or len(inputs) != self.input_size:
            logger.error(f"Invalid input shape: expected {self.input_size}, got {len(inputs) if isinstance(inputs, list) else 'invalid type'}")
            raise ValueError("Invalid input shape")
        
        inputs = np.array(inputs)
        self.hidden1 = self.sigmoid(np.dot(inputs, self.weights_ih1) + self.bias_h1)
        if dropout_rate > 0:
            self.hidden1 *= np.random.binomial(1, 1-dropout_rate, size=self.hidden1.shape) / (1-dropout_rate)
        self.hidden2 = self.sigmoid(np.dot(self.hidden1, self.weights_h1h2) + self.bias_h2)
        if dropout_rate > 0:
            self.hidden2 *= np.random.binomial(1, 1-dropout_rate, size=self.hidden2.shape) / (1-dropout_rate)
        self.output = self.sigmoid(np.dot(self.hidden2, self.weights_h2o) + self.bias_o)
        return self.output

    def backpropagate(self, inputs, targets, learning_rate):
        """Perform backpropagation to update weights and biases."""
        inputs = np.array(inputs)
        targets = np.array(targets)
        
        if inputs.shape != (self.input_size,) or targets.shape != (self.output_size,):
            logger.error(f"Invalid input or target shape: inputs={inputs.shape}, targets={targets.shape}")
            return
        
        # Forward pass
        hidden1 = self.sigmoid(np.dot(inputs, self.weights_ih1) + self.bias_h1)
        hidden2 = self.sigmoid(np.dot(hidden1, self.weights_h1h2) + self.bias_h2)
        outputs = self.sigmoid(np.dot(hidden2, self.weights_h2o) + self.bias_o)
        
        # Calculate errors
        output_errors = (targets - outputs) * self.sigmoid_derivative(outputs)
        hidden2_errors = np.dot(output_errors, self.weights_h2o.T) * self.sigmoid_derivative(hidden2)
        hidden1_errors = np.dot(hidden2_errors, self.weights_h1h2.T) * self.sigmoid_derivative(hidden1)
        
        # Update weights and biases
        self.weights_h2o += learning_rate * np.outer(hidden2, output_errors)
        self.bias_o += learning_rate * output_errors
        self.weights_h1h2 += learning_rate * np.outer(hidden1, hidden2_errors)
        self.bias_h2 += learning_rate * hidden2_errors
        self.weights_ih1 += learning_rate * np.outer(inputs, hidden1_errors)
        self.bias_h1 += learning_rate * hidden1_errors

    def train(self, input_data, target_data, epochs, learning_rate, dropout_rate=DROPOUT_RATE):
        """Train the neural network."""
        if len(input_data) != len(target_data) or not input_data:
            logger.error(f"Invalid training data: inputs={len(input_data)}, targets={len(target_data)}")
            return
        for epoch in range(epochs):
            total_error = 0.0
            for x, y in zip(input_data, target_data):
                try:
                    self.forward_propagate(x, dropout_rate)
                    self.backpropagate(x, y, learning_rate)
                    total_error += np.mean((y - self.output) ** 2)
                except ValueError as e:
                    logger.error(f"Training error: {str(e)}")
                    continue
            total_error /= len(input_data)
            if epoch % 50 == 0:
                logger.debug(f"Epoch {epoch}/{epochs} - Average Error: {total_error}")
        logger.info("Training completed.")

    def detect_threat(self):
        """Check if the current output indicates a threat."""
        return self.output[0] > THREAT_THRESHOLD

    def save_model(self, filename):
        """Save the neural network model to a file."""
        try:
            model = {
                'input_size': self.input_size,
                'hidden_size1': self.hidden_size1,
                'hidden_size2': self.hidden_size2,
                'output_size': self.output_size,
                'weights_ih1': self.weights_ih1.tolist(),
                'weights_h1h2': self.weights_h1h2.tolist(),
                'weights_h2o': self.weights_h2o.tolist(),
                'bias_h1': self.bias_h1.tolist(),
                'bias_h2': self.bias_h2.tolist(),
                'bias_o': self.bias_o.tolist()
            }
            with open(filename, 'w') as f:
                json.dump(model, f, indent=4)
            logger.info(f"Model saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save model: {str(e)}")

    def load_model(self, filename):
        """Load the neural network model from a file."""
        try:
            with open(filename, 'r') as f:
                model = json.load(f)
            self.input_size = model['input_size']
            self.hidden_size1 = model['hidden_size1']
            self.hidden_size2 = model['hidden_size2']
            self.output_size = model['output_size']
            self.weights_ih1 = np.array(model['weights_ih1'])
            self.weights_h1h2 = np.array(model['weights_h1h2'])
            self.weights_h2o = np.array(model['weights_h2o'])
            self.bias_h1 = np.array(model['bias_h1'])
            self.bias_h2 = np.array(model['bias_h2'])
            self.bias_o = np.array(model['bias_o'])
            self.output = np.zeros(self.output_size)
            logger.info(f"Model loaded from {filename}")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")

# Packet Sniffer
class PacketSniffer:
    """Packet sniffer to capture and process network packets."""
    def __init__(self, device, manager):
        self.device = device
        self.manager = manager
        self.sniffing = False
        self.sniff_thread = None

    def start(self):
        """Start packet sniffing."""
        try:
            self.sniffing = True
            self.sniff_thread = threading.Thread(target=self.sniff_packets)
            self.sniff_thread.daemon = True
            self.sniff_thread.start()
            logger.info(f"Packet sniffing started on {self.device}")
            return True
        except Exception as e:
            logger.error(f"Failed to start packet sniffer: {str(e)}")
            return False

    def stop(self):
        """Stop packet sniffing."""
        if self.sniffing:
            self.sniffing = False
            if self.sniff_thread:
                self.sniff_thread.join()
            logger.info("Packet sniffing stopped.")

    def sniff_packets(self):
        """Sniff packets on the specified interface."""
        try:
            sniff(iface=self.device, filter="ip", prn=self.packet_callback, store=0, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            logger.error(f"Error in packet sniffing: {str(e)}")

    def packet_callback(self, packet):
        """Process each captured packet."""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            size = len(packet)
            src_port = dst_port = "0"
            if TCP in packet:
                src_port = str(packet[TCP].sport)
                dst_port = str(packet[TCP].dport)
            elif UDP in packet:
                src_port = str(packet[UDP].sport)
                dst_port = str(packet[UDP].dport)
            self.manager.process_packet(src_ip, src_port, dst_ip, dst_port, size)

# Threat Intelligence Integrator
class ThreatIntelligenceIntegrator:
    """Mock threat intelligence integrator (replace with real API)."""
    def __init__(self, api_url):
        self.api_url = api_url

    def is_threat_ip(self, ip):
        """Check if an IP is a known threat (mock implementation)."""
        logger.info(f"Checking threat status for IP {ip} (mock implementation)")
        # Mock: Return True for specific IPs for testing
        return ip in ["192.168.1.100", "10.0.0.1"]

# Firewall Manager
class FirewallManager:
    """Main firewall management class."""
    def __init__(self, interface="eth0"):
        self.neural_network = NeuralNetwork()
        self.training_data = []
        self.training_labels = []
        self.connection_table = {}
        self.ip_connection_counts = {}
        self.blocked_ips = blocked_ips
        self.blocked_domains = blocked_domains
        self.panic_mode_enabled = False
        self.internet_status = False
        self.sniffer = PacketSniffer(interface, self)
        self.threat_intel = ThreatIntelligenceIntegrator(THREAT_INTEL_API)
        
        if os.path.exists(MODEL_FILE):
            self.neural_network.load_model(MODEL_FILE)
        else:
            logger.info("No model file found, initializing new neural network.")
        
        self.load_blocked_ips()
        self.load_blocked_domains()
        
        if not self.validate_interface(interface):
            logger.error(f"Invalid network interface: {interface}")
            raise ValueError(f"Invalid network interface: {interface}")
        
        if not self.sniffer.start():
            logger.error("Failed to start packet sniffer.")
            raise RuntimeError("Failed to start packet sniffer.")
        
        self.threat_monitor_thread = threading.Thread(target=self.threat_monitor)
        self.threat_monitor_thread.daemon = True
        self.threat_monitor_thread.start()
        
        self.maintenance_thread = threading.Thread(target=self.system_maintenance)
        self.maintenance_thread.daemon = True
        self.maintenance_thread.start()

    def validate_interface(self, interface):
        """Validate the network interface."""
        try:
            output = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True, check=True)
            return bool(output.stdout)
        except subprocess.CalledProcessError:
            return False

    def execute_system_command(self, cmd_args):
        """Execute a system command securely with a list of arguments."""
        try:
            result = subprocess.run(cmd_args, capture_output=True, text=True, check=True)
            logger.debug(f"Executed command: {' '.join(cmd_args)}")
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(cmd_args)} - {e.stderr}")
            return ""
        except Exception as e:
            logger.error(f"Unexpected error executing command: {' '.join(cmd_args)} - {str(e)}")
            return ""

    def apply_firewall_rules(self):
        """Apply firewall rules by reloading firewalld."""
        self.execute_system_command(["firewall-cmd", "--reload"])
        logger.info("Firewall rules applied.")

    def load_blocked_ips(self):
        """Load blocked IPs from file."""
        try:
            if not os.path.exists(BLOCKED_IPS_FILE):
                logger.info("No blocked IPs file found.")
                return
            with open(BLOCKED_IPS_FILE, 'r') as f:
                data = json.load(f)
                if not isinstance(data, dict) or "blocked_ips" not in data:
                    logger.error("Invalid blocked IPs file format.")
                    return
                self.blocked_ips.update([ip for ip in data["blocked_ips"] if self.is_valid_ip(ip)])
            logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs.")
        except json.JSONDecodeError:
            logger.error("Corrupted blocked IPs file.")
        except Exception as e:
            logger.error(f"Failed to load blocked IPs: {str(e)}")

    def save_blocked_ips(self):
        """Save blocked IPs to file."""
        try:
            with open(BLOCKED_IPS_FILE, 'w') as f:
                json.dump({"blocked_ips": list(self.blocked_ips)}, f, indent=4)
            logger.info("Saved blocked IPs to file.")
        except Exception as e:
            logger.error(f"Failed to save blocked IPs: {str(e)}")

    def load_blocked_domains(self):
        """Load blocked domains from file."""
        try:
            if not os.path.exists(BLOCKED_DOMAINS_FILE):
                logger.info("No blocked domains file found.")
                return
            with open(BLOCKED_DOMAINS_FILE, 'r') as f:
                data = json.load(f)
                if not isinstance(data, dict) or "blocked_domains" not in data:
                    logger.error("Invalid blocked domains file format.")
                    return
                for domain_data in data.get("blocked_domains", []):
                    domain = domain_data["domain"]
                    self.blocked_domains[domain] = {
                        "domain": domain,
                        "category": domain_data["category"],
                        "resolvedIPs": set([ip for ip in domain_data["resolvedIPs"] if self.is_valid_ip(ip)])
                    }
                    self.blocked_ips.update(self.blocked_domains[domain]["resolvedIPs"])
            logger.info(f"Loaded {len(self.blocked_domains)} blocked domains.")
        except json.JSONDecodeError:
            logger.error("Corrupted blocked domains file.")
        except Exception as e:
            logger.error(f"Failed to load blocked domains: {str(e)}")

    def save_blocked_domains(self):
        """Save blocked domains to file."""
        try:
            domains = [
                {
                    "domain": k,
                    "category": v["category"],
                    "resolvedIPs": list(v["resolvedIPs"])
                } for k, v in self.blocked_domains.items()
            ]
            with open(BLOCKED_DOMAINS_FILE, 'w') as f:
                json.dump({"blocked_domains": domains}, f, indent=4)
            logger.info("Saved blocked domains to file.")
        except Exception as e:
            logger.error(f"Failed to save blocked domains: {str(e)}")

    def is_valid_ip(self, ip):
        """Validate an IP address."""
        pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return bool(re.match(pattern, ip))

    def is_valid_domain(self, domain):
        """Validate a domain name."""
        pattern = r"^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})$"
        return bool(re.match(pattern, domain))

    def get_domain_category(self, domain):
        """Get the category of a domain using Webshrinker API."""
        try:
            api_key = os.getenv("WEBSHRINKER_API_KEY")
            if not api_key:
                logger.error("Webshrinker API key not set in environment variables.")
                return "unknown"
            response = requests.get(
                f"https://api.webshrinker.com/categories/v3/{domain}",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            if "categories" in data and data["categories"]:
                return data["categories"][0]
            return "unknown"
        except requests.RequestException as e:
            logger.error(f"Category request failed for {domain}: {str(e)}")
            return "unknown"

    def block_domain(self, domain, category=""):
        """Block a domain by resolving its IPs."""
        if not self.is_valid_domain(domain):
            logger.error(f"Invalid domain: {domain}")
            print(f"Invalid domain: {domain}")
            return
        import socket
        try:
            resolved_ips = []
            for info in socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM):
                ip = info[4][0]
                if self.is_valid_ip(ip) and ip not in self.blocked_ips:
                    resolved_ips.append(ip)
                    cmd = ["firewall-cmd", "--permanent", "--add-rich-rule",
                           f"rule family=\"ipv4\" source address=\"{ip}\" drop"]
                    self.execute_system_command(cmd)
                    self.blocked_ips.add(ip)
                    logger.warning(f"Blocked IP {ip} for domain {domain}")
            self.apply_firewall_rules()
            category = category or self.get_domain_category(domain)
            with global_mutex:
                self.blocked_domains[domain] = {
                    "domain": domain,
                    "category": category,
                    "resolvedIPs": set(resolved_ips)
                }
                self.save_blocked_domains()
            logger.info(f"Blocked domain {domain} (category: {category})")
            print(f"Blocked domain {domain} (category: {category})")
        except Exception as e:
            logger.error(f"Failed to resolve {domain}: {str(e)}")
            print(f"Failed to resolve {domain}: {str(e)}")

    def unblock_domain(self, domain):
        """Unblock a domain and its associated IPs."""
        with global_mutex:
            if domain not in self.blocked_domains:
                logger.info(f"Domain {domain} not blocked.")
                print(f"Domain {domain} not blocked.")
                return
            for ip in self.blocked_domains[domain]["resolvedIPs"]:
                if ip in self.blocked_ips:
                    cmd = ["firewall-cmd", "--permanent", "--remove-rich-rule",
                           f"rule family=\"ipv4\" source address=\"{ip}\" drop"]
                    self.execute_system_command(cmd)
                    self.blocked_ips.discard(ip)
                    logger.info(f"Unblocked IP {ip} for domain {domain}")
            self.apply_firewall_rules()
            del self.blocked_domains[domain]
            self.save_blocked_domains()
            logger.info(f"Unblocked domain {domain}")
            print(f"Unblocked domain {domain}")

    def block_category(self, category):
        """Block all domains in a specified category."""
        domains = {
            "sports": ["espn.com", "nfl.com", "nba.com"],
            "news": ["cnn.com", "bbc.com", "nytimes.com"],
            "technology": ["techcrunch.com", "wired.com", "theverge.com"],
            "entertainment": ["variety.com", "hollywoodreporter.com", "ew.com"],
            "finance": ["bloomberg.com", "cnbc.com", "marketwatch.com"],
            "health": ["webmd.com", "mayoclinic.org", "healthline.com"],
            "travel": ["tripadvisor.com", "lonelyplanet.com", "expedia.com"],
            "education": ["coursera.org", "edx.org", "khanacademy.org"],
            "lifestyle": ["popsugar.com", "refinery29.com", "bustle.com"],
            "science": ["sciencemag.org", "nature.com", "sciencedaily.com"],
            "gaming": ["ign.com", "gamespot.com", "polygon.com"],
            "food": ["foodnetwork.com", "bonappetit.com", "epicurious.com"],
            "fashion": ["vogue.com", "elle.com", "harpersbazaar.com"]
        }.get(category, [])
        if not domains:
            logger.warning(f"Category {category} not supported.")
            print(f"Category {category} not supported.")
            return
        with global_mutex:
            for domain in domains:
                self.block_domain(domain, category)
        logger.info(f"Blocked all domains in category: {category}")
        print(f"Blocked all domains in category: {category}")

    def unblock_category(self, category):
        """Unblock all domains in a specified category."""
        with global_mutex:
            domains_to_unblock = [k for k, v in self.blocked_domains.items() if v["category"] == category]
            for domain in domains_to_unblock:
                self.unblock_domain(domain)
        logger.info(f"Unblocked all domains in category: {category}")
        print(f"Unblocked all domains in category: {category}")

    def export_blocked_ips_to_csv(self, filename):
        """Export blocked IPs to a CSV file."""
        try:
            with open(filename, 'w') as f:
                f.write("Blocked IPs\n")
                for ip in self.blocked_ips:
                    f.write(f"{ip}\n")
            logger.info(f"Blocked IPs exported to {filename}")
        except Exception as e:
            logger.error(f"Failed to export blocked IPs: {str(e)}")

    def extract_features(self, connection):
        """Extract features from a connection for neural network input."""
        features = {
            "packetRate": 0.0,
            "packetSize": 0.0,
            "connectionDuration": 0.0,
            "portNumber": 0.0
        }
        try:
            port = float(connection["destPort"])
            features["portNumber"] = port / 65535.0
        except ValueError:
            logger.warning(f"Invalid port number: {connection['destPort']}")
        time_diff = (time.time() - connection["lastUpdate"])
        features["packetRate"] = connection["packetCount"] / time_diff if time_diff > 0 else 0.0
        features["packetSize"] = connection["totalBytes"] / (1024.0 * 1024.0)
        features["connectionDuration"] = time_diff / 3600.0
        return features

    def convert_to_vector(self, features):
        """Convert features to a vector for neural network input."""
        return [features["packetRate"], features["packetSize"], features["connectionDuration"], features["portNumber"]]

    def add_nat_rule(self, source_ip, dest_ip, port):
        """Add a NAT rule."""
        if not (self.is_valid_ip(source_ip) and self.is_valid_ip(dest_ip) and port.isdigit()):
            logger.error(f"Invalid NAT parameters: source_ip={source_ip}, dest_ip={dest_ip}, port={port}")
            return
        cmd = ["firewall-cmd", "--permanent", "--add-rich-rule",
               f"rule family=\"ipv4\" source address=\"{source_ip}\" destination address=\"{dest_ip}\" port port=\"{port}\" protocol=\"tcp\" accept"]
        self.execute_system_command(cmd)
        self.apply_firewall_rules()
        logger.info(f"Added NAT rule: {source_ip} -> {dest_ip}:{port}")

    def remove_nat_rule(self, rule_id):
        """Remove a NAT rule."""
        if not rule_id:
            logger.error("Invalid rule ID for NAT removal.")
            return
        cmd = ["firewall-cmd", "--permanent", "--remove-rich-rule", rule_id]
        self.execute_system_command(cmd)
        self.apply_firewall_rules()
        logger.info(f"Removed NAT rule: {rule_id}")

    def check_internet_connectivity(self):
        """Check internet connectivity."""
        result = subprocess.run(["ping", "-c", "1", "-W", "2", "google.com"], capture_output=True)
        self.internet_status = (result.returncode == 0)
        status = "connected" if self.internet_status else "disconnected"
        logger.info(f"Internet is {status}.")
        print(f"Internet is {status}.")

    def connect_to_vpn(self, config_path):
        """Connect to a VPN using the specified config file."""
        if not os.path.exists(config_path):
            logger.error(f"Invalid VPN config path: {config_path}")
            print(f"Invalid VPN config path: {config_path}")
            return
        if self.is_vpn_connected():
            logger.warning("VPN already connected.")
            print("VPN already connected.")
            return
        subprocess.Popen(["openvpn", "--config", config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"VPN connection initiated with config {config_path}")
        print(f"VPN connection initiated with config {config_path}")

    def disconnect_vpn(self):
        """Disconnect from VPN."""
        self.execute_system_command(["pkill", "openvpn"])
        logger.info("VPN disconnected.")
        print("VPN disconnected.")

    def is_vpn_connected(self):
        """Check if a VPN is connected."""
        result = self.execute_system_command(["pgrep", "openvpn"])
        return bool(result.strip())

    def toggle_panic_mode(self):
        """Toggle panic mode to block/unblock all traffic."""
        self.panic_mode_enabled = not self.panic_mode_enabled
        cmd = ["firewall-cmd", "--panic-on"] if self.panic_mode_enabled else ["firewall-cmd", "--panic-off"]
        self.execute_system_command(cmd)
        status = "enabled" if self.panic_mode_enabled else "disabled"
        logger.warning(f"Panic mode {status} - {'All traffic blocked' if self.panic_mode_enabled else 'Traffic restored'}.")
        print(f"Panic mode {status} - {'All traffic blocked' if self.panic_mode_enabled else 'Traffic restored'}.")

    def block_all_traffic(self):
        """Block all network traffic."""
        self.execute_system_command(["firewall-cmd", "--panic-on"])
        logger.warning("All traffic blocked.")
        print("All traffic blocked.")

    def unblock_all_traffic(self):
        """Unblock all network traffic."""
        self.execute_system_command(["firewall-cmd", "--panic-off"])
        logger.info("All traffic unblocked.")
        print("All traffic unblocked.")

    def block_ip_address(self, ip_address):
        """Block an IP address if identified as a threat."""
        if not self.is_valid_ip(ip_address):
            logger.error(f"Invalid IP address: {ip_address}")
            print(f"Invalid IP address: {ip_address}")
            return
        with global_mutex:
            if ip_address in self.blocked_ips:
                logger.info(f"IP {ip_address} already blocked.")
                print(f"IP {ip_address} already blocked.")
                return
            if self.threat_intel.is_threat_ip(ip_address):
                cmd = ["firewall-cmd", "--permanent", "--add-rich-rule",
                       f"rule family=\"ipv4\" source address=\"{ip_address}\" drop"]
                self.execute_system_command(cmd)
                self.apply_firewall_rules()
                self.blocked_ips.add(ip_address)
                self.save_blocked_ips()
                logger.warning(f"Blocked IP {ip_address} (threat intel confirmed).")
                print(f"Blocked IP {ip_address} (threat intel confirmed).")
            else:
                logger.info(f"IP {ip_address} not a known threat, not blocking.")
                print(f"IP {ip_address} not a known threat, not blocking.")

    def unblock_ip_address(self, ip_address):
        """Unblock an IP address."""
        if not self.is_valid_ip(ip_address):
            logger.error(f"Invalid IP address: {ip_address}")
            print(f"Invalid IP address: {ip_address}")
            return
        with global_mutex:
            if ip_address not in self.blocked_ips:
                logger.info(f"IP {ip_address} not blocked.")
                print(f"IP {ip_address} not blocked.")
                return
            cmd = ["firewall-cmd", "--permanent", "--remove-rich-rule",
                   f"rule family=\"ipv4\" source address=\"{ip_address}\" drop"]
            self.execute_system_command(cmd)
            self.apply_firewall_rules()
            self.blocked_ips.discard(ip_address)
            self.save_blocked_ips()
            logger.info(f"Unblocked IP {ip_address}")
            print(f"Unblocked IP {ip_address}")

    def get_geo_ip(self, ip):
        """Get geographical information for an IP address."""
        if not self.is_valid_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            print(f"Invalid IP address: {ip}")
            return
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "fail":
                logger.error(f"GeoIP API error: {data.get('message')}")
                print(f"GeoIP API error: {data.get('message')}")
                return
            country = data.get("country", "Unknown")
            city = data.get("city", "Unknown")
            message = f"GeoIP for {ip}: Country={country}, City={city}"
            logger.info(message)
            print(message)
            if country in ["North Korea", "Iran"]:
                self.block_ip_address(ip)
        except requests.RequestException as e:
            logger.error(f"GeoIP request failed: {str(e)}")
            print(f"GeoIP request failed: {str(e)}")
        time.sleep(GEOIP_RATE_LIMIT_SECONDS)

    def cleanup_expired_connections(self):
        """Clean up expired connections and collect training data."""
        now = time.time()
        temp_inputs, temp_labels = [], []
        with global_mutex:
            expired = []
            for key, conn in list(self.connection_table.items()):
                time_diff = now - conn["lastUpdate"]
                if time_diff > TIMEOUT_SECONDS:
                    features = self.extract_features(conn)
                    temp_inputs.append(self.convert_to_vector(features))
                    temp_labels.append([1.0 if conn["wasBlocked"] else 0.0])
                    expired.append(key)
            for key in expired:
                del self.connection_table[key]
            self.training_data.extend(temp_inputs)
            self.training_labels.extend(temp_labels)
        logger.info(f"Cleaned {len(temp_inputs)} expired connections.")

    def add_firewall_rule(self, action, direction, source, destination, protocol):
        """Add a firewall rule."""
        if not (self.is_valid_ip(source) or source == "0.0.0.0/0") or not self.is_valid_ip(destination):
            logger.error(f"Invalid IP in firewall rule: source={source}, destination={destination}")
            return False
        if protocol not in ["tcp", "udp"]:
            logger.error(f"Invalid protocol: {protocol}")
            return False
        rule = f"rule family=\"ipv4\" {direction} source address=\"{source}\" destination address=\"{destination}\" service name=\"{protocol}\" {action}"
        cmd = ["firewall-cmd", "--permanent", "--add-rich-rule", rule]
        output = self.execute_system_command(cmd)
        self.apply_firewall_rules()
        if "success" in output.lower():
            logger.info(f"Added firewall rule: {rule}")
            return True
        logger.error(f"Failed to add rule: {output}")
        return False

    def remove_firewall_rule(self, action, direction, source, destination, protocol):
        """Remove a firewall rule."""
        if not (self.is_valid_ip(source) or source == "0.0.0.0/0") or not self.is_valid_ip(destination):
            logger.error(f"Invalid IP in firewall rule: source={source}, destination={destination}")
            return False
        if protocol not in ["tcp", "udp"]:
            logger.error(f"Invalid protocol: {protocol}")
            return False
        rule = f"rule family=\"ipv4\" {direction} source address=\"{source}\" destination address=\"{destination}\" service name=\"{protocol}\" {action}"
        cmd = ["firewall-cmd", "--permanent", "--remove-rich-rule", rule]
        output = self.execute_system_command(cmd)
        self.apply_firewall_rules()
        if "success" in output.lower():
            logger.info(f"Removed firewall rule: {rule}")
            return True
        logger.error(f"Failed to remove rule: {output}")
        return False

    def send_notification(self, title, message):
        """Send a desktop notification."""
        cmd = ["notify-send", title, message]
        result = self.execute_system_command(cmd)
        if "error" in result.lower():
            logger.warning(f"Failed to send notification: {title}")
        else:
            logger.info(f"Notification sent: {title} - {message}")

    def rule_violation_detected(self, rule, detail):
        """Report a rule violation."""
        msg = f"Rule violation detected: {rule} - {detail}"
        logger.warning(msg)
        self.send_notification("Firewall Violation", msg)

    def detect_threat(self):
        """Detect threats across all connections."""
        threats = []
        with global_mutex:
            for key, conn in self.connection_table.items():
                features = self.extract_features(conn)
                input_vector = self.convert_to_vector(features)
                try:
                    self.neural_network.forward_propagate(input_vector)
                    if self.neural_network.detect_threat() or self.threat_intel.is_threat_ip(conn["sourceIP"]):
                        threats.append(conn["sourceIP"])
                except ValueError as e:
                    logger.error(f"Threat detection error for {conn['sourceIP']}: {str(e)}")
        return threats

    def respond_to_threat(self, ip):
        """Respond to a detected threat."""
        self.block_ip_address(ip)
        self.send_notification("Threat Detected", f"Blocked suspicious IP: {ip}")
        self.rule_violation_detected("Threat Response", f"IP {ip} blocked.")

    def train_adaptive_model(self, traffic_logs):
        """Train the neural network with traffic logs."""
        inputs, targets = [], []
        for log in traffic_logs:
            conn = {
                "sourceIP": log["sourceIP"],
                "destIP": log["destIP"],
                "packetCount": log["packetCount"],
                "totalBytes": log["bytesTransferred"],
                "lastUpdate": time.time(),
                "wasBlocked": False
            }
            features = self.extract_features(conn)
            inputs.append(self.convert_to_vector(features))
            targets.append([0.0])
        self.neural_network.train(inputs, targets, EPOCHS, LEARNING_RATE)
        threats = self.detect_threat()
        if threats:
            self.auto_heal()

    def auto_heal(self):
        """Perform auto-healing if threats are detected."""
        threats = self.detect_threat()
        if threats:
            self.toggle_panic_mode()
            time.sleep(30)  # Consider making this a constant
            self.toggle_panic_mode()
            self.rollback_rules()

    def rollback_rules(self):
        """Rollback firewall rules."""
        self.execute_system_command(["firewall-cmd", "--reload"])
        logger.info("Firewall rules rolled back.")
        print("Firewall rules rolled back.")

    def check_firewall_health(self):
        """Check the health of the firewall service."""
        output = self.execute_system_command(["firewall-cmd", "--state"])
        if "running" not in output.lower():
            self.execute_system_command(["systemctl", "restart", "firewalld"])
            logger.warning("Firewall service restarted.")
            print("Firewall service restarted.")
        else:
            logger.info("Firewall is healthy.")
            print("Firewall is healthy.")

    def optimize_firewall_rules(self):
        """Optimize firewall rules."""
        self.execute_system_command(["firewall-cmd", "--permanent", "--remove-service=http"])
        self.apply_firewall_rules()
        logger.info("Firewall rules optimized.")
        print("Firewall rules optimized.")

    def threat_monitor(self):
        """Monitor for threats periodically."""
        while running:
            self.auto_heal()
            time.sleep(THREAT_CHECK_INTERVAL_MS / 1000.0)

    def system_maintenance(self):
        """Perform system maintenance tasks."""
        while running:
            self.cleanup_expired_connections()
            self.optimize_firewall_rules()
            self.check_firewall_health()
            logger.handlers[0].doRollover()
            time.sleep(MAINTENANCE_INTERVAL_MS / 1000.0)

    def process_packet(self, source_ip, source_port, dest_ip, dest_port, size):
        """Process a captured network packet."""
        if not self.is_valid_ip(source_ip) or not self.is_valid_ip(dest_ip):
            logger.warning(f"Invalid IP detected: {source_ip} -> {dest_ip}")
            return
        key = f"{source_ip}:{source_port}->{dest_ip}:{dest_port}"
        with global_mutex:
            self.ip_connection_counts[source_ip] = self.ip_connection_counts.get(source_ip, 0) + 1
            if self.ip_connection_counts[source_ip] > CONNECTION_THRESHOLD:
                self.respond_to_threat(source_ip)
                return
            if key not in self.connection_table:
                self.connection_table[key] = {
                    "state": "NEW",
                    "sourceIP": source_ip,
                    "destIP": dest_ip,
                    "sourcePort": source_port,
                    "destPort": dest_port,
                    "lastUpdate": time.time(),
                    "packetCount": 1,
                    "totalBytes": size,
                    "wasBlocked": False
                }
            else:
                conn = self.connection_table[key]
                conn["packetCount"] += 1
                conn["totalBytes"] += size
                conn["lastUpdate"] = time.time()
            if size > AVERAGE_PACKET_SIZE * PACKET_SIZE_MULTIPLIER:
                logger.warning(f"Large packet anomaly from {source_ip}")
                self.respond_to_threat(source_ip)
                return
            features = self.extract_features(self.connection_table[key])
            input_vector = self.convert_to_vector(features)
            try:
                self.neural_network.forward_propagate(input_vector)
                if self.neural_network.detect_threat():
                    self.respond_to_threat(source_ip)
                    self.connection_table[key]["wasBlocked"] = True
            except ValueError as e:
                logger.error(f"Neural network error for {source_ip}: {str(e)}")

    def block_website(self, website):
        """Block a website by its domain."""
        self.block_domain(website)

    def train_neural_network(self):
        """Train the neural network with collected data."""
        with global_mutex:
            if len(self.training_data) != len(self.training_labels):
                logger.error(f"Mismatched training data: inputs={len(self.training_data)}, labels={len(self.training_labels)}")
                return
            if len(self.training_data) > MAX_TRAINING_SAMPLES:
                self.neural_network.train(self.training_data, self.training_labels, EPOCHS, LEARNING_RATE)
                self.training_data.clear()
                self.training_labels.clear()
                self.neural_network.save_model(MODEL_FILE)
            else:
                logger.warning(f"Insufficient samples for training: {len(self.training_data)}")

    def restore_default_config(self):
        """Restore default firewall configuration."""
        self.execute_system_command(["firewall-cmd", "--complete-reload"])
        with global_mutex:
            self.blocked_ips.clear()
            self.blocked_domains.clear()
            self.save_blocked_ips()
            self.save_blocked_domains()
        logger.info("Restored default firewall configuration.")
        print("Restored default firewall configuration.")

    def get_status(self):
        """Get the current system status."""
        return (f"Panic mode: {'Enabled' if self.panic_mode_enabled else 'Disabled'}\n"
                f"Internet: {'Connected' if self.internet_status else 'Disconnected'}\n"
                f"VPN: {'Connected' if self.is_vpn_connected() else 'Disconnected'}\n"
                f"Blocked IPs: {len(self.blocked_ips)}\n"
                f"Blocked Domains: {len(self.blocked_domains)}")

    def run_cli(self):
        """Run the command-line interface."""
        print("YUNA Firewall CLI - Type 'help' for commands.")
        while running:
            try:
                command = input("> ").strip()
                if not command:
                    continue
                parts = command.split()
                cmd = parts[0]
                args = parts[1:]
                if cmd == "exit":
                    break
                elif cmd == "help":
                    print(self.get_help_information(args[0] if args else ""))
                elif cmd == "block-ip" and args:
                    self.block_ip_address(args[0])
                elif cmd == "unblock-ip" and args:
                    self.unblock_ip_address(args[0])
                elif cmd == "panic":
                    self.toggle_panic_mode()
                elif cmd == "check-internet":
                    self.check_internet_connectivity()
                elif cmd == "geoip" and args:
                    self.get_geo_ip(args[0])
                elif cmd == "block-website" and args:
                    self.block_website(args[0])
                elif cmd == "block-domain" and args:
                    self.block_domain(args[0], args[1] if len(args) > 1 else "")
                elif cmd == "unblock-domain" and args:
                    self.unblock_domain(args[0])
                elif cmd == "block-category" and args:
                    self.block_category(args[0])
                elif cmd == "unblock-category" and args:
                    self.unblock_category(args[0])
                elif cmd == "train":
                    self.train_neural_network()
                elif cmd == "restore-default":
                    self.restore_default_config()
                elif cmd == "add-port" and len(args) >= 2:
                    self.add_firewall_rule("accept", "in", "0.0.0.0/0", args[0], args[1])
                elif cmd == "remove-port" and len(args) >= 2:
                    self.remove_firewall_rule("accept", "in", "0.0.0.0/0", args[0], args[1])
                elif cmd == "connect-vpn" and args:
                    self.connect_to_vpn(args[0])
                elif cmd == "disconnect-vpn":
                    self.disconnect_vpn()
                elif cmd == "status":
                    print(self.get_status())
                elif cmd == "export-blocked-ips" and args:
                    self.export_blocked_ips_to_csv(args[0])
                elif cmd == "add-nat" and len(args) >= 3:
                    self.add_nat_rule(args[0], args[1], args[2])
                elif cmd == "remove-nat" and args:
                    self.remove_nat_rule(args[0])
                elif cmd == "block-all":
                    self.block_all_traffic()
                elif cmd == "unblock-all":
                    self.unblock_all_traffic()
                elif cmd == "send-notification" and len(args) >= 2:
                    self.send_notification(args[0], " ".join(args[1:]))
                elif cmd == "rule-violation" and len(args) >= 2:
                    self.rule_violation_detected(args[0], " ".join(args[1:]))
                elif cmd == "detect-threat":
                    threats = self.detect_threat()
                    print(f"Threats detected: {threats if threats else 'None'}")
                elif cmd == "respond-threat" and args:
                    self.respond_to_threat(args[0])
                elif cmd == "train-adaptive":
                    print("Training adaptive model requires traffic data (not implemented for manual input).")
                elif cmd == "auto-heal":
                    self.auto_heal()
                elif cmd == "rollback":
                    self.rollback_rules()
                elif cmd == "check-health":
                    self.check_firewall_health()
                elif cmd == "optimize":
                    self.optimize_firewall_rules()
                elif cmd == "cleanup-connections":
                    self.cleanup_expired_connections()
                elif cmd == "set-log-level" and args:
                    levels = {"INFO": logging.INFO, "WARNING": logging.WARNING, "ERROR": logging.ERROR, "DEBUG": logging.DEBUG}
                    if args[0] in levels:
                        logger.setLevel(levels[args[0]])
                        logger.info(f"Logging level set to {args[0]}")
                    else:
                        print("Usage: set-log-level <INFO|WARNING|ERROR|DEBUG>")
                elif cmd == "rotate-logs":
                    logger.handlers[0].doRollover()
                elif cmd == "log-message" and len(args) >= 2:
                    levels = {"INFO": logging.INFO, "WARNING": logging.WARNING, "ERROR": logging.ERROR, "DEBUG": logging.DEBUG}
                    if args[0] in levels:
                        logger.log(levels[args[0]], " ".join(args[1:]))
                    else:
                        print("Invalid log level.")
                else:
                    print("Unknown command. Type 'help' for list of categories.")
            except Exception as e:
                logger.error(f"CLI error: {str(e)}")
                print(f"Error: {str(e)}")

    def get_help_information(self, category=""):
        """Get help information for CLI commands."""
        if not category:
            return """YUNA Firewall CLI Help Menu

Available categories (use 'help <category>' to view commands):

block - Commands for blocking and unblocking IPs/websites
firewall - Commands for managing firewall rules
network - Commands for network status and maintenance
threat - Commands for threat detection and response
vpn - Commands for VPN connections
logging - Commands for logging and notifications
status - Commands for system status and exports

exit - Quit the CLI"""
        help_text = f"YUNA Firewall CLI Commands - {category}\n\n"
        if category == "block":
            help_text += """block-ip <ip> - Block an IP address
unblock-ip <ip> - Unblock an IP address
block-website <domain> - Block a website by resolving to IP
block-domain <domain> [category] - Block a domain with optional category
unblock-domain <domain> - Unblock a domain
block-category <category> - Block all domains in a category (e.g., sports)
unblock-category <category> - Unblock all domains in a category
block-all - Block all traffic
unblock-all - Unblock all traffic"""
        elif category == "firewall":
            help_text += """add-port <port> <protocol> - Add a port rule (e.g., 80 tcp)
remove-port <port> <protocol> - Remove a port rule
add-nat <sourceIP> <destIP> <port> - Add a NAT rule
remove-nat <ruleID> - Remove a NAT rule
optimize - Optimize firewall rules
rollback - Roll back firewall rules
restore-default - Restore default firewall configuration"""
        elif category == "network":
            help_text += """check-internet - Check internet connectivity
check-health - Check firewall service health
geoip <ip> - Get geographical information for an IP
cleanup-connections - Clean up expired connections"""
        elif category == "threat":
            help_text += """detect-threat - Check if a threat is detected
respond-threat <ip> - Respond to a threat by blocking an IP
train - Train the neural network with collected data
train-adaptive - Train adaptive model (not implemented for manual input)
auto-heal - Trigger auto-heal process"""
        elif category == "vpn":
            help_text += """connect-vpn <config_path> - Connect to VPN
disconnect-vpn - Disconnect from VPN"""
        elif category == "logging":
            help_text += """send-notification <title> <message> - Send a desktop notification
rule-violation <rule> <detail> - Report a rule violation
set-log-level <INFO|WARNING|ERROR|DEBUG> - Set logging level
rotate-logs - Rotate log files
log-message <INFO|WARNING|ERROR|DEBUG> <message> - Log a custom message"""
        elif category == "status":
            help_text += """status - Show current system status
export-blocked-ips <filename> - Export blocked IPs to a CSV file"""
        else:
            help_text = f"Unknown category: {category}\n\nUse 'help' to see available categories."
        return help_text

# GUI
class GUIMainWindow(QMainWindow):
    """GUI for the YUNA Firewall Manager."""
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self.dark_mode = False
        self.setWindowTitle("YUNA Firewall Manager")
        self.setMinimumSize(800, 600)
        
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        
        tabs = QTabWidget()
        tabs.addTab(self.create_block_tab(), "Block")
        tabs.addTab(self.create_firewall_tab(), "Firewall")
        tabs.addTab(self.create_network_tab(), "Network")
        tabs.addTab(self.create_threat_tab(), "Threat")
        tabs.addTab(self.create_vpn_tab(), "VPN")
        tabs.addTab(self.create_logging_tab(), "Logging")
        tabs.addTab(self.create_status_tab(), "Status")
        
        main_layout = QVBoxLayout()
        main_layout.addWidget(tabs)
        main_layout.addWidget(QLabel("Status Output:"))
        main_layout.addWidget(self.status_text)
        
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)
        
        self.apply_theme()

    def apply_theme(self):
        """Apply light or dark theme to the GUI."""
        if self.dark_mode:
            self.setStyleSheet("""
                QMainWindow, QWidget { background-color: #353b48; color: #f5f6fa; }
                QTextEdit { background-color: #2f3640; color: #f5f6fa; border: 1px solid #487eb0; }
                QPushButton { 
                    background-color: #487eb0; color: #f5f6fa; border: none; 
                    padding: 5px 15px; border-radius: 3px; 
                }
                QPushButton:hover { background-color: #54a0ff; }
                QLineEdit { 
                    background-color: #2f3640; color: #f5f6fa; 
                    border: 1px solid #487eb0; padding: 3px;
                }
                QComboBox { 
                    background-color: #2f3640; color: #f5f6fa; 
                    border: 1px solid #487eb0; padding: 3px;
                }
                QTabWidget::pane { border: 1px solid #487eb0; }
                QTabBar::tab { 
                    background-color: #353b48; color: #f5f6fa; 
                    padding: 8px 20px; border: 1px solid #487eb0; 
                }
                QTabBar::tab:selected { background-color: #487eb0; }
                QLabel { color: #f5f6fa; }
            """)
        else:
            self.setStyleSheet("""
                QMainWindow, QWidget { background-color: white; color: #333333; }
                QTextEdit { 
                    background-color: white; color: #333333; 
                    border: 2px solid #dcdde1; font-size: 12px;
                }
                QPushButton { 
                    background-color: #2980b9; color: white; 
                    border: none; padding: 8px 15px; border-radius: 4px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #3498db; }
                QLineEdit { 
                    background-color: white; color: #333333; 
                    border: 2px solid #dcdde1; padding: 5px; border-radius: 4px;
                }
                QComboBox { 
                    background-color: white; color: #333333; 
                    border: 2px solid #dcdde1; padding: 5px; border-radius: 4px;
                }
                QTabWidget::pane { border: 2px solid #dcdde1; background: white; }
                QTabBar::tab { 
                    background-color: #f5f6fa; color: #333333; 
                    padding: 10px 20px; border: 1px solid #dcdde1;
                    border-radius: 4px 4px 0 0; margin-right: 2px; font-weight: bold;
                }
                QTabBar::tab:selected { background-color: #2980b9; color: white; }
                QLabel { color: #333333; font-size: 12px; margin: 2px; }
            """)

    def toggle_theme(self):
        """Toggle between light and dark themes."""
        self.dark_mode = not self.dark_mode
        self.apply_theme()

    def create_block_tab(self):
        """Create the Block tab for the GUI."""
        tab = QWidget()
        layout = QGridLayout()
        row = 0
        
        layout.addWidget(QLabel("IP Address:"), row, 0)
        ip_input = QLineEdit()
        layout.addWidget(ip_input, row, 1)
        block_ip_btn = QPushButton("Block IP")
        block_ip_btn.clicked.connect(lambda: self.manager.block_ip_address(ip_input.text()) if ip_input.text() else self.status_text.append("Error: Enter an IP address."))
        layout.addWidget(block_ip_btn, row, 2)
        unblock_ip_btn = QPushButton("Unblock IP")
        unblock_ip_btn.clicked.connect(lambda: self.manager.unblock_ip_address(ip_input.text()) if ip_input.text() else self.status_text.append("Error: Enter an IP address."))
        layout.addWidget(unblock_ip_btn, row, 3)
        row += 1
        
        layout.addWidget(QLabel("Website Domain:"), row, 0)
        website_input = QLineEdit()
        layout.addWidget(website_input, row, 1)
        block_website_btn = QPushButton("Block Website")
        block_website_btn.clicked.connect(lambda: self.manager.block_website(website_input.text()) if website_input.text() else self.status_text.append("Error: Enter a website domain."))
        layout.addWidget(block_website_btn, row, 2)
        row += 1
        
        layout.addWidget(QLabel("Domain:"), row, 0)
        domain_input = QLineEdit()
        layout.addWidget(domain_input, row, 1)
        layout.addWidget(QLabel("Category (optional):"), row + 1, 0)
        cat_input = QLineEdit()
        layout.addWidget(cat_input, row + 1, 1)
        block_domain_btn = QPushButton("Block Domain")
        block_domain_btn.clicked.connect(lambda: self.manager.block_domain(domain_input.text(), cat_input.text()) if domain_input.text() else self.status_text.append("Error: Enter a domain."))
        layout.addWidget(block_domain_btn, row, 2)
        unblock_domain_btn = QPushButton("Unblock Domain")
        unblock_domain_btn.clicked.connect(lambda: self.manager.unblock_domain(domain_input.text()) if domain_input.text() else self.status_text.append("Error: Enter a domain."))
        layout.addWidget(unblock_domain_btn, row, 3)
        row += 2
        
        layout.addWidget(QLabel("Category:"), row, 0)
        category_combo = QComboBox()
        category_combo.addItems(["sports", "news", "technology", "entertainment", "finance", "health", "travel", "education", "lifestyle", "science", "gaming", "food", "fashion"])
        layout.addWidget(category_combo, row, 1)
        block_cat_btn = QPushButton("Block Category")
        block_cat_btn.clicked.connect(lambda: self.manager.block_category(category_combo.currentText()))
        layout.addWidget(block_cat_btn, row, 2)
        unblock_cat_btn = QPushButton("Unblock Category")
        unblock_cat_btn.clicked.connect(lambda: self.manager.unblock_category(category_combo.currentText()))
        layout.addWidget(unblock_cat_btn, row, 3)
        row += 1
        
        block_all_btn = QPushButton("Block All Traffic")
        block_all_btn.clicked.connect(self.manager.block_all_traffic)
        layout.addWidget(block_all_btn, row, 0, 1, 2)
        unblock_all_btn = QPushButton("Unblock All Traffic")
        unblock_all_btn.clicked.connect(self.manager.unblock_all_traffic)
        layout.addWidget(unblock_all_btn, row, 2, 1, 2)
        
        tab.setLayout(layout)
        return tab

    def create_firewall_tab(self):
        """Create the Firewall tab for the GUI."""
        tab = QWidget()
        layout = QGridLayout()
        row = 0
        
        layout.addWidget(QLabel("Port:"), row, 0)
        port_input = QLineEdit()
        layout.addWidget(port_input, row, 1)
        layout.addWidget(QLabel("Protocol:"), row, 2)
        proto_combo = QComboBox()
        proto_combo.addItems(["tcp", "udp"])
        layout.addWidget(proto_combo, row, 3)
        row += 1
        add_port_btn = QPushButton("Add Port")
        add_port_btn.clicked.connect(lambda: self.manager.add_firewall_rule("accept", "in", "0.0.0.0/0", port_input.text(), proto_combo.currentText()) if port_input.text() else self.status_text.append("Error: Enter a port."))
        layout.addWidget(add_port_btn, row, 0, 1, 2)
        remove_port_btn = QPushButton("Remove Port")
        remove_port_btn.clicked.connect(lambda: self.manager.remove_firewall_rule("accept", "in", "0.0.0.0/0", port_input.text(), proto_combo.currentText()) if port_input.text() else self.status_text.append("Error: Enter a port."))
        layout.addWidget(remove_port_btn, row, 2, 1, 2)
        row += 1
        
        layout.addWidget(QLabel("Source IP:"), row, 0)
        src_ip_input = QLineEdit()
        layout.addWidget(src_ip_input, row, 1)
        row += 1
        layout.addWidget(QLabel("Destination IP:"), row, 0)
        dest_ip_input = QLineEdit()
        layout.addWidget(dest_ip_input, row, 1)
        row += 1
        layout.addWidget(QLabel("Port:"), row, 0)
        nat_port_input = QLineEdit()
        layout.addWidget(nat_port_input, row, 1)
        add_nat_btn = QPushButton("Add NAT Rule")
        add_nat_btn.clicked.connect(lambda: self.manager.add_nat_rule(src_ip_input.text(), dest_ip_input.text(), nat_port_input.text()) if src_ip_input.text() and dest_ip_input.text() and nat_port_input.text() else self.status_text.append("Error: Fill all fields for NAT."))
        layout.addWidget(add_nat_btn, row, 2)
        row += 1
        
        layout.addWidget(QLabel("Rule ID:"), row, 0)
        rule_id_input = QLineEdit()
        layout.addWidget(rule_id_input, row, 1)
        remove_nat_btn = QPushButton("Remove NAT Rule")
        remove_nat_btn.clicked.connect(lambda: self.manager.remove_nat_rule(rule_id_input.text()) if rule_id_input.text() else self.status_text.append("Error: Enter rule ID."))
        layout.addWidget(remove_nat_btn, row, 2)
        row += 1
        
        optimize_btn = QPushButton("Optimize Rules")
        optimize_btn.clicked.connect(self.manager.optimize_firewall_rules)
        layout.addWidget(optimize_btn, row, 0)
        rollback_btn = QPushButton("Rollback Rules")
        rollback_btn.clicked.connect(self.manager.rollback_rules)
        layout.addWidget(rollback_btn, row, 1)
        restore_btn = QPushButton("Restore Default")
        restore_btn.clicked.connect(self.manager.restore_default_config)
        layout.addWidget(restore_btn, row, 2)
        
        tab.setLayout(layout)
        return tab

    def create_network_tab(self):
        """Create the Network tab for the GUI."""
        tab = QWidget()
        layout = QVBoxLayout()
        
        check_internet_btn = QPushButton("Check Internet Connectivity")
        check_internet_btn.clicked.connect(self.manager.check_internet_connectivity)
        layout.addWidget(check_internet_btn)
        
        check_health_btn = QPushButton("Check Firewall Health")
        check_health_btn.clicked.connect(self.manager.check_firewall_health)
        layout.addWidget(check_health_btn)
        
        geo_ip_layout = QHBoxLayout()
        geo_ip_label = QLabel("IP for GeoIP:")
        geo_ip_input = QLineEdit()
        geo_ip_btn = QPushButton("Get GeoIP")
        geo_ip_btn.clicked.connect(lambda: self.manager.get_geo_ip(geo_ip_input.text()) if geo_ip_input.text() else self.status_text.append("Error: Enter an IP."))
        geo_ip_layout.addWidget(geo_ip_label)
        geo_ip_layout.addWidget(geo_ip_input)
        geo_ip_layout.addWidget(geo_ip_btn)
        layout.addLayout(geo_ip_layout)
        
        cleanup_btn = QPushButton("Cleanup Expired Connections")
        cleanup_btn.clicked.connect(self.manager.cleanup_expired_connections)
        layout.addWidget(cleanup_btn)
        
        tab.setLayout(layout)
        return tab

    def create_threat_tab(self):
        """Create the Threat tab for the GUI."""
        tab = QWidget()
        layout = QVBoxLayout()
        
        detect_threat_btn = QPushButton("Detect Threat")
        detect_threat_btn.clicked.connect(lambda: self.status_text.append(f"Threats detected: {self.manager.detect_threat() if self.manager.detect_threat() else 'None'}"))
        layout.addWidget(detect_threat_btn)
        
        respond_layout = QHBoxLayout()
        respond_ip_label = QLabel("IP to Respond:")
        respond_ip_input = QLineEdit()
        respond_threat_btn = QPushButton("Respond to Threat")
        respond_threat_btn.clicked.connect(lambda: self.manager.respond_to_threat(respond_ip_input.text()) if respond_ip_input.text() else self.status_text.append("Error: Enter an IP."))
        respond_layout.addWidget(respond_ip_label)
        respond_layout.addWidget(respond_ip_input)
        respond_layout.addWidget(respond_threat_btn)
        layout.addLayout(respond_layout)
        
        train_btn = QPushButton("Train Neural Network")
        train_btn.clicked.connect(self.manager.train_neural_network)
        layout.addWidget(train_btn)
        
        auto_heal_btn = QPushButton("Auto Heal")
        auto_heal_btn.clicked.connect(self.manager.auto_heal)
        layout.addWidget(auto_heal_btn)
        
        tab.setLayout(layout)
        return tab

    def create_vpn_tab(self):
        """Create the VPN tab for the GUI."""
        tab = QWidget()
        layout = QVBoxLayout()
        
        connect_layout = QHBoxLayout()
        config_label = QLabel("VPN Config Path:")
        config_input = QLineEdit()
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(lambda: config_input.setText(QFileDialog.getOpenFileName(None, "Select VPN Config", "", "Config Files (*.ovpn)")[0]))
        connect_vpn_btn = QPushButton("Connect VPN")
        connect_vpn_btn.clicked.connect(lambda: self.manager.connect_to_vpn(config_input.text()) if config_input.text() else self.status_text.append("Error: Enter config path."))
        connect_layout.addWidget(config_label)
        connect_layout.addWidget(config_input)
        connect_layout.addWidget(browse_btn)
        connect_layout.addWidget(connect_vpn_btn)
        layout.addLayout(connect_layout)
        
        disconnect_vpn_btn = QPushButton("Disconnect VPN")
        disconnect_vpn_btn.clicked.connect(self.manager.disconnect_vpn)
        layout.addWidget(disconnect_vpn_btn)
        
        tab.setLayout(layout)
        return tab

    def create_logging_tab(self):
        """Create the Logging tab for the GUI."""
        tab = QWidget()
        layout = QGridLayout()
        row = 0
        
        layout.addWidget(QLabel("Title:"), row, 0)
        title_input = QLineEdit()
        layout.addWidget(title_input, row, 1)
        row += 1
        layout.addWidget(QLabel("Message:"), row, 0)
        msg_input = QLineEdit()
        layout.addWidget(msg_input, row, 1)
        send_notif_btn = QPushButton("Send Notification")
        send_notif_btn.clicked.connect(lambda: self.manager.send_notification(title_input.text(), msg_input.text()) if title_input.text() and msg_input.text() else self.status_text.append("Error: Fill title and message."))
        layout.addWidget(send_notif_btn, row, 2)
        row += 1
        
        layout.addWidget(QLabel("Rule:"), row, 0)
        rule_input = QLineEdit()
        layout.addWidget(rule_input, row, 1)
        row += 1
        layout.addWidget(QLabel("Detail:"), row, 0)
        detail_input = QLineEdit()
        layout.addWidget(detail_input, row, 1)
        violation_btn = QPushButton("Report Violation")
        violation_btn.clicked.connect(lambda: self.manager.rule_violation_detected(rule_input.text(), detail_input.text()) if rule_input.text() and detail_input.text() else self.status_text.append("Error: Fill rule and detail."))
        layout.addWidget(violation_btn, row, 2)
        row += 1
        
        layout.addWidget(QLabel("Log Level:"), row, 0)
        log_level_combo = QComboBox()
        log_level_combo.addItems(["INFO", "WARNING", "ERROR", "DEBUG"])
        layout.addWidget(log_level_combo, row, 1)
        set_log_level_btn = QPushButton("Set Log Level")
        set_log_level_btn.clicked.connect(lambda: logger.setLevel({"INFO": logging.INFO, "WARNING": logging.WARNING, "ERROR": logging.ERROR, "DEBUG": logging.DEBUG}[log_level_combo.currentText()]))
        layout.addWidget(set_log_level_btn, row, 2)
        row += 1
        
        rotate_logs_btn = QPushButton("Rotate Logs")
        rotate_logs_btn.clicked.connect(lambda: logger.handlers[0].doRollover())
        layout.addWidget(rotate_logs_btn, row, 0)
        
        layout.addWidget(QLabel("Level:"), row, 1)
        custom_level_combo = QComboBox()
        custom_level_combo.addItems(["INFO", "WARNING", "ERROR", "DEBUG"])
        layout.addWidget(custom_level_combo, row, 2)
        row += 1
        layout.addWidget(QLabel("Message:"), row, 0)
        custom_msg_input = QLineEdit()
        layout.addWidget(custom_msg_input, row, 1)
        log_msg_btn = QPushButton("Log Message")
        log_msg_btn.clicked.connect(lambda: logger.log({"INFO": logging.INFO, "WARNING": logging.WARNING, "ERROR": logging.ERROR, "DEBUG": logging.DEBUG}[custom_level_combo.currentText()], custom_msg_input.text()) if custom_msg_input.text() else None)
        layout.addWidget(log_msg_btn, row, 2)
        
        tab.setLayout(layout)
        return tab

    def create_status_tab(self):
        """Create the Status tab for the GUI."""
        tab = QWidget()
        layout = QVBoxLayout()
        
        show_status_btn = QPushButton("Show Status")
        show_status_btn.clicked.connect(lambda: self.status_text.append(self.manager.get_status()))
        layout.addWidget(show_status_btn)
        
        theme_btn = QPushButton("Toggle Dark/Light Mode")
        theme_btn.clicked.connect(self.toggle_theme)
        layout.addWidget(theme_btn)
        
        export_layout = QHBoxLayout()
        export_label = QLabel("Export Filename:")
        export_input = QLineEdit()
        export_btn = QPushButton("Export Blocked IPs")
        export_btn.clicked.connect(lambda: self.manager.export_blocked_ips_to_csv(export_input.text()) if export_input.text() else self.status_text.append("Error: Enter filename."))
        export_layout.addWidget(export_label)
        export_layout.addWidget(export_input)
        export_layout.addWidget(export_btn)
        layout.addLayout(export_layout)
        
        tab.setLayout(layout)
        return tab

def display_banner():
    """Display the YUNA Firewall banner."""
    print("""
    ██╗ ██╗██╗ ██╗███╗ ██╗ █████╗
    ╚██╗ ██╔╝██║ ██║████╗ ██║██╔══██╗
     ╚████╔╝ ██║ ██║██╔██╗ ██║███████║
      ╚██╔╝ ██║ ██║██║╚██╗██║██╔══██║
       ██║ ╚██████╔╝██║ ╚████║██║ ██║
       ╚═╝ ╚═════╝ ╚═╝ ╚═══╝╚═╝ ╚═╝
        Firewall Management System
    """)

def main():
    """Main entry point for the YUNA Firewall Manager."""
    display_banner()
    logger.setLevel(logging.DEBUG)
    logger.handlers[0].doRollover()
    interface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    try:
        manager = FirewallManager(interface)
        if len(sys.argv) > 2 and sys.argv[2] == "gui":
            app = QApplication(sys.argv)
            window = GUIMainWindow(manager)
            window.show()
            sys.exit(app.exec_())
        else:
            manager.run_cli()
    except Exception as e:
        logger.error(f"Startup error: {str(e)}")
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()