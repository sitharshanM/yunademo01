#include "IpsEngine.h"
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <iostream>
#include <ctime>
#include <algorithm>

using json = nlohmann::json;

#define IPS_RULES_FILE "ips_rules.json"
#define IPS_ALERTS_FILE "ips_alerts.json"

IpsEngine::IpsEngine() : rulesFilePath(IPS_RULES_FILE), alertsFilePath(IPS_ALERTS_FILE) {
    loadRules();
    loadAlerts();

    // Add some default rules if the rules list is empty
    if (rules.empty()) {
        addRule("drop tcp any any -> any 80 (msg:\"SQL Injection Attempt detected in payload\"; content:\"UNION SELECT\"; sid:10001;)");
        addRule("drop tcp any any -> any 80 (msg:\"Cross Site Scripting (XSS) payload detected\"; content:\"<script>\"; sid:10002;)");
        addRule("drop tcp any any -> any 22 (msg:\"Suspicious SSH Command Execution\"; content:\"/etc/passwd\"; sid:10003;)");
        saveRules();
    }
}

IpsEngine::~IpsEngine() {
    saveRules();
    saveAlerts();
}

std::string IpsEngine::getCurrentTimestamp() {
    std::time_t now = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buf);
}

void IpsEngine::loadRules() {
    std::ifstream file(rulesFilePath);
    if (!file.is_open()) return;
    json j;
    try {
        file >> j;
        if (j.contains("rules") && j["rules"].is_array()) {
            rules.clear();
            for (const auto& item : j["rules"]) {
                IpsRule rule;
                rule.sid = item.value("sid", 0);
                rule.action = item.value("action", "alert");
                rule.protocol = item.value("protocol", "any");
                rule.srcIp = item.value("srcIp", "any");
                rule.srcPort = item.value("srcPort", 0);
                rule.destIp = item.value("destIp", "any");
                rule.destPort = item.value("destPort", 0);
                rule.pattern = item.value("pattern", "");
                rule.message = item.value("message", "");
                rule.enabled = item.value("enabled", true);
                rules.push_back(rule);
            }
        }
    } catch (...) {}
    file.close();
}

void IpsEngine::saveRules() {
    json j;
    json ruleList = json::array();
    for (const auto& rule : rules) {
        json item;
        item["sid"] = rule.sid;
        item["action"] = rule.action;
        item["protocol"] = rule.protocol;
        item["srcIp"] = rule.srcIp;
        item["srcPort"] = rule.srcPort;
        item["destIp"] = rule.destIp;
        item["destPort"] = rule.destPort;
        item["pattern"] = rule.pattern;
        item["message"] = rule.message;
        item["enabled"] = rule.enabled;
        ruleList.push_back(item);
    }
    j["rules"] = ruleList;
    std::ofstream file(rulesFilePath);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
    }
}

void IpsEngine::loadAlerts() {
    std::ifstream file(alertsFilePath);
    if (!file.is_open()) return;
    json j;
    try {
        file >> j;
        if (j.contains("alerts") && j["alerts"].is_array()) {
            alerts.clear();
            for (const auto& item : j["alerts"]) {
                IpsAlertRecord rec;
                rec.timestamp = item.value("timestamp", "");
                rec.sid = item.value("sid", 0);
                rec.message = item.value("message", "");
                rec.violatorIP = item.value("violatorIP", "");
                rec.targetedPort = item.value("targetedPort", 0);
                rec.action = item.value("action", "Alerted");
                alerts.push_back(rec);
            }
        }
    } catch (...) {}
    file.close();
}

void IpsEngine::saveAlerts() {
    json j;
    json alertList = json::array();
    for (const auto& rec : alerts) {
        json item;
        item["timestamp"] = rec.timestamp;
        item["sid"] = rec.sid;
        item["message"] = rec.message;
        item["violatorIP"] = rec.violatorIP;
        item["targetedPort"] = rec.targetedPort;
        item["action"] = rec.action;
        alertList.push_back(item);
    }
    j["alerts"] = alertList;
    std::ofstream file(alertsFilePath);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
    }
}

// Parses: action proto srcIP srcPort -> destIP destPort (options)
// e.g.: drop tcp any any -> any 80 (msg:"SQL attempt"; content:"UNION"; sid:123;)
bool IpsEngine::addRule(const std::string& ruleStr) {
    if (ruleStr.empty()) return false;

    // Find the options block
    size_t optStart = ruleStr.find('(');
    size_t optEnd = ruleStr.rfind(')');
    if (optStart == std::string::npos || optEnd == std::string::npos || optEnd <= optStart) {
        return false;
    }

    std::string header = ruleStr.substr(0, optStart);
    std::string options = ruleStr.substr(optStart + 1, optEnd - optStart - 1);

    // Parse header tokens
    std::istringstream iss(header);
    std::vector<std::string> tokens;
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }

    // Must have at least: action proto srcIp srcPort -> destIp destPort
    // e.g. ["drop", "tcp", "any", "any", "->", "any", "80"] -> size 7
    if (tokens.size() < 7 || tokens[4] != "->") {
        return false;
    }

    IpsRule rule;
    rule.action = tokens[0];
    rule.protocol = tokens[1];
    rule.srcIp = tokens[2];
    
    // Parse srcPort
    if (tokens[3] == "any") rule.srcPort = 0;
    else {
        try { rule.srcPort = std::stoi(tokens[3]); } catch (...) { return false; }
    }

    rule.destIp = tokens[5];
    
    // Parse destPort
    if (tokens[6] == "any") rule.destPort = 0;
    else {
        try { rule.destPort = std::stoi(tokens[6]); } catch (...) { return false; }
    }

    // Parse options
    std::vector<std::string> opts;
    std::string opt;
    std::istringstream optStream(options);
    while (std::getline(optStream, opt, ';')) {
        // Trim leading spaces
        size_t first = opt.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        opt = opt.substr(first);

        size_t colon = opt.find(':');
        if (colon == std::string::npos) continue;

        std::string key = opt.substr(0, colon);
        std::string val = opt.substr(colon + 1);

        // Strip quotes if they exist
        if (val.front() == '"' && val.back() == '"') {
            val = val.substr(1, val.size() - 2);
        }

        if (key == "msg") {
            rule.message = val;
        } else if (key == "content") {
            rule.pattern = val;
        } else if (key == "sid") {
            try { rule.sid = std::stoi(val); } catch (...) { return false; }
        }
    }

    if (rule.sid == 0) {
        // Generate an SID if not specified
        std::lock_guard<std::mutex> lock(ipsMutex);
        int maxSid = 20000;
        for (const auto& r : rules) {
            if (r.sid > maxSid) maxSid = r.sid;
        }
        rule.sid = maxSid + 1;
    }

    {
        std::lock_guard<std::mutex> lock(ipsMutex);
        // Remove existing rule if same SID
        auto it = std::remove_if(rules.begin(), rules.end(), [&rule](const IpsRule& r) {
            return r.sid == rule.sid;
        });
        rules.erase(it, rules.end());

        rules.push_back(rule);
        saveRules();
    }

    Logger::log("IPS Engine: Compiled and added rule SID " + std::to_string(rule.sid), Logger::INFO);
    return true;
}

bool IpsEngine::deleteRule(int sid) {
    std::lock_guard<std::mutex> lock(ipsMutex);
    auto it = std::remove_if(rules.begin(), rules.end(), [sid](const IpsRule& r) {
        return r.sid == sid;
    });
    if (it != rules.end()) {
        rules.erase(it, rules.end());
        saveRules();
        Logger::log("IPS Engine: Deleted rule SID " + std::to_string(sid), Logger::INFO);
        return true;
    }
    return false;
}

void IpsEngine::toggleRule(int sid, bool enabled) {
    std::lock_guard<std::mutex> lock(ipsMutex);
    for (auto& rule : rules) {
        if (rule.sid == sid) {
            rule.enabled = enabled;
            saveRules();
            Logger::log("IPS Engine: Toggled rule SID " + std::to_string(sid) + " to " + (enabled ? "Enabled" : "Disabled"), Logger::INFO);
            break;
        }
    }
}

std::vector<IpsRule> IpsEngine::getRules() {
    std::lock_guard<std::mutex> lock(ipsMutex);
    return rules;
}

std::vector<IpsAlertRecord> IpsEngine::getAlerts() {
    std::lock_guard<std::mutex> lock(ipsMutex);
    return alerts;
}

void IpsEngine::clearAlerts() {
    std::lock_guard<std::mutex> lock(ipsMutex);
    alerts.clear();
    saveAlerts();
}

bool IpsEngine::matchIp(const std::string& pattern, const std::string& ip) {
    if (pattern == "any") return true;
    return pattern == ip;
}

bool IpsEngine::matchPort(int rulePort, int packetPort) {
    if (rulePort == 0) return true;
    return rulePort == packetPort;
}

bool IpsEngine::inspectPacket(const std::string& protocol, const std::string& srcIp, int srcPort,
                             const std::string& destIp, int destPort, const std::string& payload,
                             IpsRule& matchedRule) {
    std::lock_guard<std::mutex> lock(ipsMutex);
    for (const auto& rule : rules) {
        if (!rule.enabled) continue;

        // 1. Match protocol (case insensitive comparison or wildcard)
        if (rule.protocol != "any") {
            std::string ruleProto = rule.protocol;
            std::string pktProto = protocol;
            std::transform(ruleProto.begin(), ruleProto.end(), ruleProto.begin(), ::tolower);
            std::transform(pktProto.begin(), pktProto.end(), pktProto.begin(), ::tolower);
            if (ruleProto != pktProto) continue;
        }

        // 2. Match IP directions
        if (!matchIp(rule.srcIp, srcIp) || !matchIp(rule.destIp, destIp)) continue;

        // 3. Match ports
        if (!matchPort(rule.srcPort, srcPort) || !matchPort(rule.destPort, destPort)) continue;

        // 4. Match payload pattern
        if (!rule.pattern.empty()) {
            if (payload.find(rule.pattern) == std::string::npos) {
                // Try case-insensitive search as fallback
                std::string payLower = payload;
                std::string patLower = rule.pattern;
                std::transform(payLower.begin(), payLower.end(), payLower.begin(), ::tolower);
                std::transform(patLower.begin(), patLower.end(), patLower.begin(), ::tolower);
                if (payLower.find(patLower) == std::string::npos) {
                    continue;
                }
            }
        }

        // Trigger found!
        matchedRule = rule;
        
        // Log alert record
        IpsAlertRecord alert;
        alert.timestamp = getCurrentTimestamp();
        alert.sid = rule.sid;
        alert.message = rule.message;
        alert.violatorIP = srcIp;
        alert.targetedPort = destPort;
        alert.action = (rule.action == "drop") ? "Blocked" : "Alerted";
        
        alerts.push_back(alert);
        if (alerts.size() > 500) {
            alerts.erase(alerts.begin());
        }
        
        // Save alerts to file
        json j;
        json alertList = json::array();
        for (const auto& rec : alerts) {
            json item;
            item["timestamp"] = rec.timestamp;
            item["sid"] = rec.sid;
            item["message"] = rec.message;
            item["violatorIP"] = rec.violatorIP;
            item["targetedPort"] = rec.targetedPort;
            item["action"] = rec.action;
            alertList.push_back(item);
        }
        j["alerts"] = alertList;
        std::ofstream file(alertsFilePath);
        if (file.is_open()) {
            file << j.dump(4);
            file.close();
        }

        return true;
    }
    return false;
}

void IpsEngine::logAlert(const IpsRule& rule, const std::string& violatorIP, int port) {
    std::lock_guard<std::mutex> lock(ipsMutex);
    IpsAlertRecord alert;
    alert.timestamp = getCurrentTimestamp();
    alert.sid = rule.sid;
    alert.message = rule.message;
    alert.violatorIP = violatorIP;
    alert.targetedPort = port;
    alert.action = (rule.action == "drop") ? "Blocked" : "Alerted";
    
    alerts.push_back(alert);
    if (alerts.size() > 500) {
        alerts.erase(alerts.begin());
    }
    saveAlerts();
}
