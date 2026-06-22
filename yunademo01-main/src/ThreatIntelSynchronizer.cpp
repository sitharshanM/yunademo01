#include "ThreatIntelSynchronizer.h"
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <curl/curl.h>
#include <arpa/inet.h>
#include <unistd.h>

using json = nlohmann::json;

#define SYNC_THREAT_IPS_FILE "sync_threat_ips.json"
#define THREAT_FEEDS_FILE "threat_feeds.json"

static size_t curlWriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    std::string* mem = static_cast<std::string*>(userp);
    mem->append(static_cast<char*>(contents), realsize);
    return realsize;
}

ThreatIntelSynchronizer::ThreatIntelSynchronizer() 
    : running(false), forceSync(false), syncIntervalHours(24), databaseFile(SYNC_THREAT_IPS_FILE) {
    loadFeedUrls();
    loadSynchronizedIPs();
    
    // Provide a default list if none exist
    if (feedUrls.empty()) {
        feedUrls.push_back("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/compromised_ips.ipset");
        feedUrls.push_back("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/honeypot_ips.ipset");
        saveFeedUrls();
    }
}

ThreatIntelSynchronizer::~ThreatIntelSynchronizer() {
    stopAutoSync();
    saveSynchronizedIPs();
}

void ThreatIntelSynchronizer::loadFeedUrls() {
    std::ifstream file(THREAT_FEEDS_FILE);
    if (!file.is_open()) {
        return;
    }
    json j;
    try {
        file >> j;
        if (j.contains("feeds") && j["feeds"].is_array()) {
            feedUrls.clear();
            for (const auto& url : j["feeds"]) {
                feedUrls.push_back(url.get<std::string>());
            }
        }
        syncIntervalHours = j.value("interval_hours", 24);
    } catch (...) {}
    file.close();
}

void ThreatIntelSynchronizer::saveFeedUrls() {
    json j;
    j["feeds"] = feedUrls;
    j["interval_hours"] = syncIntervalHours.load();
    std::ofstream file(THREAT_FEEDS_FILE);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
    }
}

void ThreatIntelSynchronizer::loadSynchronizedIPs() {
    std::ifstream file(databaseFile);
    if (!file.is_open()) {
        Logger::log("Threat Sync: No cached database found.", Logger::INFO);
        return;
    }
    json j;
    try {
        file >> j;
        if (j.contains("ips") && j["ips"].is_array()) {
            std::lock_guard<std::mutex> lock(syncMutex);
            synchronizedIPs.clear();
            for (const auto& ip : j["ips"]) {
                synchronizedIPs.insert(ip.get<std::string>());
            }
            Logger::log("Threat Sync: Loaded " + std::to_string(synchronizedIPs.size()) + " cached threat IPs.", Logger::INFO);
        }
    } catch (...) {}
    file.close();
}

void ThreatIntelSynchronizer::saveSynchronizedIPs() {
    json j;
    json ipList = json::array();
    {
        std::lock_guard<std::mutex> lock(syncMutex);
        for (const auto& ip : synchronizedIPs) {
            ipList.push_back(ip);
        }
    }
    j["ips"] = ipList;
    std::ofstream file(databaseFile);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
        Logger::log("Threat Sync: Database saved.", Logger::INFO);
    }
}

bool ThreatIntelSynchronizer::addFeedUrl(const std::string& url) {
    if (url.empty()) return false;
    auto it = std::find(feedUrls.begin(), feedUrls.end(), url);
    if (it != feedUrls.end()) return false;
    feedUrls.push_back(url);
    saveFeedUrls();
    Logger::log("Threat Sync: Added feed URL: " + url, Logger::INFO);
    return true;
}

bool ThreatIntelSynchronizer::removeFeedUrl(const std::string& url) {
    auto it = std::find(feedUrls.begin(), feedUrls.end(), url);
    if (it == feedUrls.end()) return false;
    feedUrls.erase(it);
    saveFeedUrls();
    Logger::log("Threat Sync: Removed feed URL: " + url, Logger::INFO);
    return true;
}

std::vector<std::string> ThreatIntelSynchronizer::getFeedUrls() {
    return feedUrls;
}

bool ThreatIntelSynchronizer::isThreatIP(const std::string& ip) {
    std::lock_guard<std::mutex> lock(syncMutex);
    return synchronizedIPs.count(ip) > 0;
}

size_t ThreatIntelSynchronizer::getThreatIPCount() {
    std::lock_guard<std::mutex> lock(syncMutex);
    return synchronizedIPs.size();
}

void ThreatIntelSynchronizer::triggerSync() {
    forceSync = true;
}

void ThreatIntelSynchronizer::syncNow() {
    Logger::log("Threat Sync: Starting manual synchronization run...", Logger::INFO);
    std::vector<std::string> urlsCopy = feedUrls;
    size_t countBefore = getThreatIPCount();
    
    for (const auto& url : urlsCopy) {
        std::string response;
        Logger::log("Threat Sync: Fetching " + url, Logger::INFO);
        if (downloadFeed(url, response)) {
            parseAndMergeIPs(response);
        } else {
            Logger::log("Threat Sync: Failed to fetch feed: " + url, Logger::WARNING);
        }
    }
    
    saveSynchronizedIPs();
    size_t countAfter = getThreatIPCount();
    Logger::log("Threat Sync: Complete. Synchronized IP Count: " + std::to_string(countAfter) + " (Added " + std::to_string(countAfter - countBefore) + ")", Logger::INFO);
}

bool ThreatIntelSynchronizer::downloadFeed(const std::string& url, std::string& response) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L); // 15 second timeout
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // follow redirects
    
    // Disable certificate verify warning if requested or for simplicity in testing
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); 

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK);
}

void ThreatIntelSynchronizer::parseAndMergeIPs(const std::string& data) {
    std::lock_guard<std::mutex> lock(syncMutex);
    std::istringstream stream(data);
    std::string line;
    size_t addedCount = 0;

    // Simple regex or check for standard IPv4 address
    while (std::getline(stream, line)) {
        // Strip comment parts
        size_t comment = line.find('#');
        if (comment != std::string::npos) {
            line = line.substr(0, comment);
        }
        comment = line.find("//");
        if (comment != std::string::npos) {
            line = line.substr(0, comment);
        }

        // Trim whitespace
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        line.erase(0, line.find_first_not_of(" \t\r\n"));

        if (line.empty()) continue;

        // Strip subnets (CIDR) like /24 for checks (optionally block base IP or expand, here we store the base IP)
        size_t slash = line.find('/');
        std::string ipPart = (slash != std::string::npos) ? line.substr(0, slash) : line;

        // Validate IP
        struct sockaddr_in sa;
        struct sockaddr_in6 sa6;
        if (inet_pton(AF_INET, ipPart.c_str(), &(sa.sin_addr)) == 1 ||
            inet_pton(AF_INET6, ipPart.c_str(), &(sa6.sin6_addr)) == 1) {
            synchronizedIPs.insert(ipPart);
            addedCount++;
        }
    }
    
    Logger::log("Threat Sync: Parsed and merged " + std::to_string(addedCount) + " IPs from feed.", Logger::INFO);
}

void ThreatIntelSynchronizer::startAutoSync(int intervalHours) {
    if (running.load()) {
        return;
    }
    syncIntervalHours = intervalHours;
    running = true;
    syncThread = std::thread(&ThreatIntelSynchronizer::runSyncLoop, this);
    Logger::log("Threat Sync: Auto-sync thread started.", Logger::INFO);
}

void ThreatIntelSynchronizer::stopAutoSync() {
    if (running.load()) {
        running = false;
        if (syncThread.joinable()) {
            syncThread.join();
        }
        Logger::log("Threat Sync: Auto-sync thread stopped.", Logger::INFO);
    }
}

void ThreatIntelSynchronizer::runSyncLoop() {
    // Run an initial synchronization check shortly after startup
    sleep(5); 
    syncNow();

    while (running.load()) {
        // Sleep in small increments to check for shutdown or forced syncs
        int checkIntervalSeconds = 60;
        int targetSeconds = syncIntervalHours.load() * 3600;
        int elapsedSeconds = 0;

        while (elapsedSeconds < targetSeconds && running.load() && !forceSync.load()) {
            sleep(checkIntervalSeconds);
            elapsedSeconds += checkIntervalSeconds;
        }

        if (!running.load()) break;

        // Perform synchronization
        syncNow();
        forceSync = false;
    }
}
