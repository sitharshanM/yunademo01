# YUNA Firewall Management System

## Overview
The YUNA Firewall Management System is a robust and intelligent firewall solution designed to monitor, manage, and secure network traffic. It integrates advanced features such as neural network-based threat detection, domain blocking, and VPN management.

## Features
- **Neural Network-Based Threat Detection**: Detects suspicious network activity using a trained neural network.
- **Domain and IP Blocking**: Block specific domains, categories, or IP addresses.
- **VPN Management**: Connect to and disconnect from VPNs.
- **Firewall Rule Management**: Add, remove, and optimize firewall rules.
- **GeoIP Lookup**: Retrieve geographical information for IP addresses.
- **Logging and Notifications**: Detailed logging with log rotation and desktop notifications.
- **CLI Interface**: Interactive command-line interface for managing the firewall.

## Installation
1. Clone the repository:
   ```bash
   git clone <repository-url>
   ```
2. Navigate to the project directory:
   ```bash
   cd yunademo01
   ```
3. Install dependencies:
   - Ensure `libpcap`, `libcurl`, and `readline` libraries are installed.
   - Install the required packages:
     ```bash
     sudo apt-get install libpcap-dev libcurl4-openssl-dev libreadline-dev
     ```
4. Compile the project:
   ```bash
   g++ -std=c++17 -o yuna_firewall yuna1.cpp -lpcap -lcurl -lreadline -lpthread
   ```

## Usage
1. Run the program:
   ```bash
   ./yuna_firewall
   ```
2. Use the CLI commands to manage the firewall. Type `help` to see available commands.

## CLI Commands
- `block-ip <ip>`: Block an IP address.
- `unblock-ip <ip>`: Unblock an IP address.
- `block-domain <domain> [category]`: Block a domain with an optional category.
- `unblock-domain <domain>`: Unblock a domain.
- `block-category <category>`: Block all domains in a category.
- `unblock-category <category>`: Unblock all domains in a category.
- `connect-vpn <config_path>`: Connect to a VPN using the specified configuration file.
- `disconnect-vpn`: Disconnect from the VPN.
- `check-internet`: Check internet connectivity.
- `detect-threat`: Check if a threat is detected.
- `status`: Display the current system status.
- `help`: Display the help menu.

## Configuration Files
- `blocked_ips.json`: Stores the list of blocked IPs.
- `blocked_domains.json`: Stores the list of blocked domains and their categories.
- `neural_model.json`: Stores the trained neural network model.

## Technical Details
- **Programming Language**: C++
- **Libraries Used**:
  - `libpcap`: For packet sniffing.
  - `libcurl`: For making HTTP requests.
  - `readline`: For interactive CLI.
  - `nlohmann/json`: For JSON parsing.
- **Neural Network**:
  - Input: 4 features (packet rate, packet size, connection duration, port number).
  - Architecture: 2 hidden layers with dropout.
  - Output: Threat probability.

## Logging
Logs are stored in `~/FirewallManagerLogs/firewall_manager.log`. Logs are rotated when they exceed 10 MB.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

## Support
For issues or questions, please open an issue in the repository or contact the maintainer.

# Technical Documentation

## System Architecture
The YUNA Firewall Management System is designed with modular components to ensure scalability, maintainability, and performance. Below is an overview of the system's architecture:

### Components
1. **Neural Network**:
   - Implements a multi-layer perceptron for threat detection.
   - Features:
     - Input: Packet rate, packet size, connection duration, port number.
     - Hidden Layers: Two layers with dropout regularization.
     - Output: Probability of a threat.
   - Trained using backpropagation with a mean squared error loss function.

2. **Packet Sniffer**:
   - Captures live network traffic using `libpcap`.
   - Filters packets based on IP protocol.
   - Extracts source/destination IPs, ports, and packet size.

3. **Firewall Manager**:
   - Manages firewall rules using `firewalld` commands.
   - Supports blocking/unblocking of IPs, domains, and categories.
   - Provides NAT rule management.

4. **Threat Intelligence Integrator**:
   - Queries external threat intelligence APIs to validate IPs.
   - Example API: `https://api.threatintel.example.com`.

5. **Logger**:
   - Logs system events with encryption.
   - Supports log rotation when file size exceeds 10 MB.

6. **CLI Interface**:
   - Interactive command-line interface for user interaction.
   - Provides autocompletion and help commands.

## Data Flow
1. **Packet Capture**:
   - The `PacketSniffer` captures packets and forwards them to the `FirewallManager`.
2. **Feature Extraction**:
   - The `FirewallManager` extracts features (e.g., packet rate, size) from the connection state.
3. **Threat Detection**:
   - The `NeuralNetwork` processes the features and outputs a threat probability.
   - If the probability exceeds the threshold, the connection is flagged as a threat.
4. **Response**:
   - The `FirewallManager` blocks the IP or domain associated with the threat.
   - Notifications are sent to the user.

## Key Algorithms
### Neural Network Training
- **Forward Propagation**:
  - Computes activations for each layer using the sigmoid activation function.
- **Backpropagation**:
  - Updates weights and biases using gradient descent.
  - Learning rate: `0.01`.
- **Dropout Regularization**:
  - Randomly sets a fraction of activations to zero during training to prevent overfitting.

### Packet Processing
1. Parse packet headers to extract IPs, ports, and protocol.
2. Update connection state (e.g., packet count, total bytes).
3. Detect anomalies (e.g., large packets, high connection rates).
4. Forward features to the neural network for threat detection.

## Configuration
### Constants
- `TIMEOUT_SECONDS`: 3600 (1 hour).
- `THREAT_THRESHOLD`: 0.7 (probability threshold for threats).
- `PACKET_RATE_THRESHOLD`: 100 packets/second.
- `AVERAGE_PACKET_SIZE`: 512 bytes.
- `MODEL_FILE`: `neural_model.json` (path to the saved model).

### Files
- `blocked_ips.json`: Stores blocked IPs.
- `blocked_domains.json`: Stores blocked domains and their categories.
- `firewall_manager.log`: Stores logs.

## API Integration
### Threat Intelligence API
- **Endpoint**: `https://api.threatintel.example.com/query`
- **Method**: `GET`
- **Headers**:
  - `Authorization: Bearer <API_KEY>`
- **Response**:
  ```json
  {
    "ip": "192.168.1.1",
    "threat": true
  }
  ```

## Error Handling
- **Packet Sniffer**:
  - Logs errors if the network interface cannot be opened.
- **Firewall Commands**:
  - Logs warnings if a command fails.
- **Neural Network**:
  - Validates input dimensions before training.

## Future Enhancements
1. **Web Interface**:
   - Develop a web-based dashboard for managing the firewall.
2. **Advanced Threat Detection**:
   - Integrate machine learning models for anomaly detection.
3. **Real-Time Alerts**:
   - Send email or SMS notifications for critical threats.
4. **Multi-Platform Support**:
   - Extend compatibility to Windows and macOS.

## Contact
For technical support, please contact the maintainer at `support@example.com`.