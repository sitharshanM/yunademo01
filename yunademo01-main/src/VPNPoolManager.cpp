#include "VPNPoolManager.h"
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <unistd.h>
#include <algorithm>

using json = nlohmann::json;

#define VPN_POOL_FILE "vpn_pool.json"

VPNPoolManager::VPNPoolManager() : activeProfileName(""), running(false), checkIntervalSeconds(15), pingTimeoutSeconds(2) {
    loadPoolConfig();
}

VPNPoolManager::~VPNPoolManager() {
    stopHealthMonitor();
    disconnectActive();
    savePoolConfig();
}

std::string VPNPoolManager::executeSystemCommand(const std::string& cmd) {
    std::string result = "";
    char buffer[128];
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return "";
    }
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
    return result;
}

void VPNPoolManager::loadPoolConfig() {
    std::ifstream file(VPN_POOL_FILE);
    if (!file.is_open()) {
        Logger::log("VPN Pool: No pool config file found.", Logger::INFO);
        return;
    }
    json j;
    try {
        file >> j;
        if (j.contains("profiles") && j["profiles"].is_array()) {
            std::lock_guard<std::mutex> lock(poolMutex);
            profiles.clear();
            for (const auto& item : j["profiles"]) {
                VPNProfile profile;
                profile.name = item.value("name", "");
                profile.type = item.value("type", "");
                profile.configPath = item.value("configPath", "");
                profile.isConnected = false;
                if (!profile.name.empty() && !profile.configPath.empty()) {
                    profiles.push_back(profile);
                }
            }
        }
        activeProfileName = j.value("activeProfileName", "");
        Logger::log("VPN Pool: Config loaded successfully.", Logger::INFO);
    } catch (const std::exception& e) {
        Logger::log("VPN Pool: Error loading config: " + std::string(e.what()), Logger::ERROR);
    }
    file.close();
}

void VPNPoolManager::savePoolConfig() {
    json j;
    json profList = json::array();
    {
        std::lock_guard<std::mutex> lock(poolMutex);
        for (const auto& profile : profiles) {
            json item;
            item["name"] = profile.name;
            item["type"] = profile.type;
            item["configPath"] = profile.configPath;
            profList.push_back(item);
        }
    }
    j["profiles"] = profList;
    j["activeProfileName"] = activeProfileName;

    std::ofstream file(VPN_POOL_FILE);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
        Logger::log("VPN Pool: Config saved.", Logger::INFO);
    } else {
        Logger::log("VPN Pool: Failed to save config.", Logger::ERROR);
    }
}

bool VPNPoolManager::addProfile(const std::string& name, const std::string& type, const std::string& configPath) {
    if (name.empty() || configPath.empty() || (type != "wireguard" && type != "openvpn")) {
        Logger::log("VPN Pool: Invalid profile details provided for add.", Logger::ERROR);
        return false;
    }
    
    // Check if configuration file exists
    if (access(configPath.c_str(), F_OK) != 0) {
        Logger::log("VPN Pool: Config file does not exist at " + configPath, Logger::ERROR);
        return false;
    }

    std::lock_guard<std::mutex> lock(poolMutex);
    auto it = std::find_if(profiles.begin(), profiles.end(), [&](const VPNProfile& p) { return p.name == name; });
    if (it != profiles.end()) {
        Logger::log("VPN Pool: Profile with name " + name + " already exists.", Logger::WARNING);
        return false;
    }

    VPNProfile profile;
    profile.name = name;
    profile.type = type;
    profile.configPath = configPath;
    profile.isConnected = false;
    profiles.push_back(profile);
    
    Logger::log("VPN Pool: Added profile " + name + " (" + type + ")", Logger::INFO);
    
    savePoolConfig();
    return true;
}

bool VPNPoolManager::removeProfile(const std::string& name) {
    std::lock_guard<std::mutex> lock(poolMutex);
    auto it = std::find_if(profiles.begin(), profiles.end(), [&](const VPNProfile& p) { return p.name == name; });
    if (it == profiles.end()) {
        Logger::log("VPN Pool: Profile not found for removal: " + name, Logger::WARNING);
        return false;
    }

    if (it->isConnected) {
        Logger::log("VPN Pool: Cannot remove active connected profile. Disconnect first.", Logger::WARNING);
        return false;
    }

    profiles.erase(it);
    Logger::log("VPN Pool: Removed profile " + name, Logger::INFO);
    
    if (activeProfileName == name) {
        activeProfileName = "";
    }

    savePoolConfig();
    return true;
}

std::vector<VPNProfile> VPNPoolManager::getProfiles() {
    std::lock_guard<std::mutex> lock(poolMutex);
    return profiles;
}

bool VPNPoolManager::connectProfile(const std::string& name) {
    disconnectActive();

    std::lock_guard<std::mutex> lock(poolMutex);
    auto it = std::find_if(profiles.begin(), profiles.end(), [&](VPNProfile& p) { return p.name == name; });
    if (it == profiles.end()) {
        Logger::log("VPN Pool: Connection profile not found: " + name, Logger::ERROR);
        return false;
    }

    Logger::log("VPN Pool: Connecting to profile " + name + "...", Logger::INFO);
    std::string cmd;
    if (it->type == "wireguard") {
        cmd = "wg-quick up " + it->configPath + " 2>&1";
    } else { // openvpn
        cmd = "openvpn --config " + it->configPath + " --daemon 2>&1";
    }

    std::string output = executeSystemCommand(cmd);
    Logger::log("VPN Pool Command Output: " + output, Logger::DEBUG);

    // Briefly sleep to allow interface/daemon initialization
    usleep(500000); 

    // Validate connectivity
    it->isConnected = isVPNConnected();
    if (it->isConnected) {
        activeProfileName = name;
        Logger::log("VPN Pool: Connected to " + name, Logger::INFO);
        savePoolConfig();
        return true;
    } else {
        Logger::log("VPN Pool: Failed to connect to " + name, Logger::ERROR);
        return false;
    }
}

void VPNPoolManager::disconnectActive() {
    std::lock_guard<std::mutex> lock(poolMutex);
    if (activeProfileName.empty()) {
        return;
    }

    auto it = std::find_if(profiles.begin(), profiles.end(), [&](VPNProfile& p) { return p.name == activeProfileName; });
    if (it != profiles.end()) {
        Logger::log("VPN Pool: Disconnecting active profile " + activeProfileName + "...", Logger::INFO);
        std::string cmd;
        if (it->type == "wireguard") {
            cmd = "wg-quick down " + it->configPath + " 2>&1";
        } else { // openvpn
            cmd = "pkill openvpn 2>&1";
        }
        executeSystemCommand(cmd);
        it->isConnected = false;
    }
    
    activeProfileName = "";
    savePoolConfig();
}

bool VPNPoolManager::isVPNConnected() {
    // Check if openvpn is running or any wg interfaces are showing
    std::string opvCheck = executeSystemCommand("pgrep openvpn");
    if (!opvCheck.empty()) {
        return true;
    }
    std::string wgCheck = executeSystemCommand("wg show");
    if (!wgCheck.empty() && wgCheck.find("interface") != std::string::npos) {
        return true;
    }
    return false;
}

std::string VPNPoolManager::getActiveProfileName() {
    std::lock_guard<std::mutex> lock(poolMutex);
    return activeProfileName;
}

bool VPNPoolManager::pingHost(const std::string& host) {
    std::string cmd = "ping -c 1 -W " + std::to_string(pingTimeoutSeconds) + " " + host + " > /dev/null 2>&1";
    int status = system(cmd.c_str());
    return (status == 0);
}

void VPNPoolManager::startHealthMonitor(int intervalSeconds) {
    if (running.load()) {
        return;
    }
    checkIntervalSeconds = intervalSeconds;
    running = true;
    healthMonitorThread = std::thread(&VPNPoolManager::monitorHealth, this);
    Logger::log("VPN Pool: Health monitor thread started.", Logger::INFO);
}

void VPNPoolManager::stopHealthMonitor() {
    if (running.load()) {
        running = false;
        if (healthMonitorThread.joinable()) {
            healthMonitorThread.join();
        }
        Logger::log("VPN Pool: Health monitor thread stopped.", Logger::INFO);
    }
}

void VPNPoolManager::monitorHealth() {
    while (running.load()) {
        // Sleep iteration with interval checking
        for (int i = 0; i < checkIntervalSeconds && running.load(); ++i) {
            sleep(1);
        }
        if (!running.load()) break;

        std::string active = getActiveProfileName();
        if (!active.empty()) {
            // Ping test Google DNS/Cloudflare DNS through the system to see if the connection is active
            if (!pingHost("1.1.1.1") && !pingHost("8.8.8.8")) {
                Logger::log("VPN Pool: Health check failed for active VPN profile: " + active + ". Initiating failover...", Logger::WARNING);
                performFailover();
            }
        }
    }
}

bool VPNPoolManager::performFailover() {
    std::lock_guard<std::mutex> lock(poolMutex);
    if (profiles.size() <= 1) {
        Logger::log("VPN Pool: Failover failed. No other profile available in the pool.", Logger::ERROR);
        return false;
    }

    std::string currentActive = activeProfileName;
    auto currentIt = std::find_if(profiles.begin(), profiles.end(), [&](const VPNProfile& p) { return p.name == currentActive; });
    
    // Find next profile
    size_t currentIndex = (currentIt != profiles.end()) ? std::distance(profiles.begin(), currentIt) : 0;
    size_t nextIndex = (currentIndex + 1) % profiles.size();
    
    std::string nextProfileName = profiles[nextIndex].name;
    
    // Unlock poolMutex before calling connectProfile to avoid deadlock (connectProfile locks it again)
    poolMutex.unlock();
    
    Logger::log("VPN Pool: Switching from " + currentActive + " to failover target: " + nextProfileName, Logger::WARNING);
    bool success = connectProfile(nextProfileName);
    
    poolMutex.lock(); // re-acquire lock for callers/safety
    return success;
}
