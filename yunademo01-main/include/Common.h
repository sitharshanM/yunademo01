#ifndef COMMON_H
#define COMMON_H

#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <map>
#include <unordered_map>
#include <set>
#include <chrono>
#include <thread>
#include <mutex>
#include <random>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <cstdlib>
#include <atomic>
#include <condition_variable>
#include <future>
#include <queue>
#include <regex>
#include <csignal>
#include <limits>
#include <cstring>

#include <unistd.h>

// Struct definitions
struct BlockedDomain {
    std::string domain;
    std::string category;             // e.g., "sports", "news"
    std::set<std::string> resolvedIPs; // IPs resolved from the domain
};

struct NetworkFeatures {
    double packetRate;
    double packetSize;
    double connectionDuration;
    double portNumber;
    double payloadEntropy;
    double flagAnomaly;
};

struct ConnectionState {
    std::string state;
    std::string sourceIP;
    std::string destIP;
    std::string sourcePort;
    std::string destPort;
    std::chrono::system_clock::time_point lastUpdate;
    int packetCount;
    long long totalBytes;
    bool wasBlocked;
    double accumulatedEntropy;
    double accumulatedAnomalies;
};

struct NetworkTrafficData {
    std::string sourceIP;
    std::string destIP;
    int packetCount;
    long long bytesTransferred;
};

struct FirewallRule {
    std::string action;
    std::string direction;
    std::string source;
    std::string destination;
    std::string protocol;
};

struct CategorySchedule {
    int startHour = 0;
    int endHour = 0;
    bool enabled = false;
    bool isCurrentlyBlocked = false;
};

struct LivePacketRecord {
    std::string timestamp;
    std::string protocol;
    std::string sourceIP;
    std::string sourcePort;
    std::string destIP;
    std::string destPort;
    int size;
    std::string status; // "Allowed", "Blocked", "Flagged"
};

// Constants
#define TIMEOUT_SECONDS 3600
#define MAX_TRAINING_SAMPLES 1000
#define LEARNING_RATE 0.01
#define EPOCHS 500
#define THREAT_THRESHOLD 0.7
#define PACKET_RATE_THRESHOLD 100.0
#define CONNECTION_THRESHOLD 50
#define AVERAGE_PACKET_SIZE 512
#define PACKET_SIZE_MULTIPLIER 5
#define MAINTENANCE_INTERVAL_MS 3600000
#define THREAT_CHECK_INTERVAL_MS 10000
#define LOG_ROTATION_SIZE 10485760
#define DROPOUT_RATE 0.2
#define BATCH_SIZE 32
#define MODEL_FILE "neural_model.json"
#define CONFIG_FILE "yuna_config.json"
#define BLOCKED_IPS_FILE "blocked_ips.json"
#define BLOCKED_DOMAINS_FILE "blocked_domains.json"
#define THREAT_INTEL_API "https://api.threatintel.example.com/query"

// Global variables declarations
extern std::mutex globalMutex;
extern std::atomic<bool> running;
extern std::set<std::string>* blockedIPsPtr;
extern std::map<std::string, BlockedDomain>* blockedDomainsPtr;

#endif // COMMON_H
