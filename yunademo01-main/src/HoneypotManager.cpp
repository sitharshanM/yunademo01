#include "HoneypotManager.h"
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <algorithm>
#include <ctime>

using json = nlohmann::json;

#define HONEYPOT_CONFIG_FILE "honeypot_config.json"
#define HONEYPOT_TRIGGERS_FILE "honeypot_triggers.json"

HoneypotManager::HoneypotManager() : running(false) {
    loadHoneypotConfig();
    loadTriggerHistory();
    
    if (trapPorts.empty()) {
        trapPorts = {21, 23, 8080}; // Default common ports
        saveHoneypotConfig();
    }
}

HoneypotManager::~HoneypotManager() {
    stopHoneypot();
    saveTriggerHistory();
}

std::string HoneypotManager::getCurrentTimestamp() {
    std::time_t now = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buf);
}

void HoneypotManager::loadHoneypotConfig() {
    std::ifstream file(HONEYPOT_CONFIG_FILE);
    if (!file.is_open()) return;
    json j;
    try {
        file >> j;
        if (j.contains("trap_ports") && j["trap_ports"].is_array()) {
            trapPorts.clear();
            for (const auto& port : j["trap_ports"]) {
                trapPorts.push_back(port.get<int>());
            }
        }
    } catch (...) {}
    file.close();
}

void HoneypotManager::saveHoneypotConfig() {
    json j;
    j["trap_ports"] = trapPorts;
    std::ofstream file(HONEYPOT_CONFIG_FILE);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
    }
}

void HoneypotManager::loadTriggerHistory() {
    std::ifstream file(HONEYPOT_TRIGGERS_FILE);
    if (!file.is_open()) return;
    json j;
    try {
        file >> j;
        if (j.contains("triggers") && j["triggers"].is_array()) {
            triggers.clear();
            for (const auto& item : j["triggers"]) {
                HoneypotTriggerRecord rec;
                rec.timestamp = item.value("timestamp", "");
                rec.violatorIP = item.value("violatorIP", "");
                rec.port = item.value("port", 0);
                rec.status = item.value("status", "Blocked");
                triggers.push_back(rec);
            }
        }
    } catch (...) {}
    file.close();
}

void HoneypotManager::saveTriggerHistory() {
    json j;
    json trigList = json::array();
    for (const auto& rec : triggers) {
        json item;
        item["timestamp"] = rec.timestamp;
        item["violatorIP"] = rec.violatorIP;
        item["port"] = rec.port;
        item["status"] = rec.status;
        trigList.push_back(item);
    }
    j["triggers"] = trigList;
    std::ofstream file(HONEYPOT_TRIGGERS_FILE);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
    }
}

void HoneypotManager::setTriggerCallback(std::function<void(const std::string&, int)> callback) {
    std::lock_guard<std::mutex> lock(honeypotMutex);
    triggerCallback = callback;
}

bool HoneypotManager::addTrapPort(int port) {
    if (port < 1 || port > 65535) return false;
    std::lock_guard<std::mutex> lock(honeypotMutex);
    auto it = std::find(trapPorts.begin(), trapPorts.end(), port);
    if (it != trapPorts.end()) return false;
    
    trapPorts.push_back(port);
    saveHoneypotConfig();
    
    // If honeypot is currently running, spawn listener for the new port
    if (running.load()) {
        listenerThreads.push_back(std::thread(&HoneypotManager::listenOnPort, this, port));
    }
    
    return true;
}

bool HoneypotManager::removeTrapPort(int port) {
    std::lock_guard<std::mutex> lock(honeypotMutex);
    auto it = std::find(trapPorts.begin(), trapPorts.end(), port);
    if (it == trapPorts.end()) return false;
    
    trapPorts.erase(it);
    saveHoneypotConfig();
    
    // We need to re-apply / restart honeypot if running to close the specific port
    if (running.load()) {
        honeypotMutex.unlock();
        stopHoneypot();
        startHoneypot();
        honeypotMutex.lock();
    }
    
    return true;
}

std::vector<int> HoneypotManager::getTrapPorts() {
    std::lock_guard<std::mutex> lock(honeypotMutex);
    return trapPorts;
}

std::vector<HoneypotTriggerRecord> HoneypotManager::getTriggers() {
    std::lock_guard<std::mutex> lock(honeypotMutex);
    return triggers;
}

void HoneypotManager::clearTriggers() {
    std::lock_guard<std::mutex> lock(honeypotMutex);
    triggers.clear();
    saveTriggerHistory();
}

void HoneypotManager::startHoneypot() {
    if (running.load()) return;
    running = true;
    
    std::lock_guard<std::mutex> lock(honeypotMutex);
    listenerThreads.clear();
    listenerSockets.clear();
    
    Logger::log("Honeypot: Starting active trap listeners on ports...", Logger::INFO);
    for (int port : trapPorts) {
        listenerThreads.push_back(std::thread(&HoneypotManager::listenOnPort, this, port));
    }
}

void HoneypotManager::stopHoneypot() {
    if (!running.load()) return;
    running = false;
    
    {
        std::lock_guard<std::mutex> lock(honeypotMutex);
        // Closing the sockets will cause select() and accept() to drop / fail
        for (int sock : listenerSockets) {
            close(sock);
        }
        listenerSockets.clear();
    }
    
    for (auto& th : listenerThreads) {
        if (th.joinable()) {
            th.join();
        }
    }
    
    std::lock_guard<std::mutex> lock(honeypotMutex);
    listenerThreads.clear();
    Logger::log("Honeypot: All trap listeners stopped.", Logger::INFO);
}

void HoneypotManager::listenOnPort(int port) {
    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
        Logger::log("Honeypot: Failed to create socket for port " + std::to_string(port), Logger::ERROR);
        return;
    }
    
    int opt = 1;
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(serverFd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        Logger::log("Honeypot: Bind failed for port " + std::to_string(port), Logger::ERROR);
        close(serverFd);
        return;
    }
    
    if (listen(serverFd, 5) < 0) {
        Logger::log("Honeypot: Listen failed for port " + std::to_string(port), Logger::ERROR);
        close(serverFd);
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(honeypotMutex);
        listenerSockets.push_back(serverFd);
    }
    
    Logger::log("Honeypot: Trap listener active on port " + std::to_string(port), Logger::INFO);
    
    while (running.load()) {
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(serverFd, &readFds);
        
        struct timeval tv;
        tv.tv_sec = 1; // 1 second timeout
        tv.tv_usec = 0;
        
        int selectRet = select(serverFd + 1, &readFds, nullptr, nullptr, &tv);
        if (selectRet > 0) {
            struct sockaddr_in clientAddr;
            socklen_t addrLen = sizeof(clientAddr);
            int clientFd = accept(serverFd, (struct sockaddr*)&clientAddr, &addrLen);
            if (clientFd >= 0) {
                char ipBuf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &clientAddr.sin_addr, ipBuf, sizeof(ipBuf));
                std::string violatorIP = ipBuf;
                
                close(clientFd); // Hang up immediately
                
                Logger::log("Honeypot TRIGGER: Unauthorized connection to trap port " + std::to_string(port) + " from " + violatorIP, Logger::WARNING);
                
                // Record trigger
                HoneypotTriggerRecord record;
                record.timestamp = getCurrentTimestamp();
                record.violatorIP = violatorIP;
                record.port = port;
                record.status = "Blocked";
                
                {
                    std::lock_guard<std::mutex> lock(honeypotMutex);
                    triggers.push_back(record);
                    if (triggers.size() > 500) {
                        triggers.erase(triggers.begin());
                      }
                      saveTriggerHistory();
                  }
                  
                  // Call FirewallManager block trigger hook
                  if (triggerCallback) {
                      triggerCallback(violatorIP, port);
                  }
              }
          }
      }
      
      close(serverFd);
      Logger::log("Honeypot: Closed trap listener on port " + std::to_string(port), Logger::INFO);
  }
