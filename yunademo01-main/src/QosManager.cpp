#include "QosManager.h"
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <unistd.h>
#include <algorithm>

using json = nlohmann::json;

#define QOS_RULES_FILE "qos_rules.json"

QosManager::QosManager(const std::string& interface) : interfaceName(interface), nextClassId(11) {
    loadRulesConfig();
    initQdisc();
    reapplyAllRules();
}

QosManager::~QosManager() {
    clearSystemQdisc();
    saveRulesConfig();
}

std::string QosManager::executeSystemCommand(const std::string& cmd) {
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

void QosManager::initQdisc() {
    Logger::log("QoS: Initializing queuing discipline on " + interfaceName, Logger::INFO);
    
    // Clear existing qdisc
    clearSystemQdisc();

    // Add root HTB qdisc
    std::string cmd = "tc qdisc add dev " + interfaceName + " root handle 1: htb default 10 2>&1";
    std::string out = executeSystemCommand(cmd);
    Logger::log("QoS: Root qdisc output: " + out, Logger::DEBUG);

    // Add default class (full speed, e.g. 1gbps)
    cmd = "tc class add dev " + interfaceName + " parent 1: classid 1:10 htb rate 1000mbit ceil 1000mbit 2>&1";
    out = executeSystemCommand(cmd);
    Logger::log("QoS: Default class output: " + out, Logger::DEBUG);
}

void QosManager::clearSystemQdisc() {
    Logger::log("QoS: Resetting traffic control rules on " + interfaceName, Logger::INFO);
    std::string cmd = "tc qdisc del dev " + interfaceName + " root 2>&1";
    executeSystemCommand(cmd);
}

void QosManager::loadRulesConfig() {
    std::ifstream file(QOS_RULES_FILE);
    if (!file.is_open()) {
        Logger::log("QoS: No rules config file found.", Logger::INFO);
        return;
    }
    json j;
    try {
        file >> j;
        if (j.contains("rules") && j["rules"].is_array()) {
            std::lock_guard<std::mutex> lock(qosMutex);
            rules.clear();
            for (const auto& item : j["rules"]) {
                QosRule rule;
                rule.id = item.value("id", "");
                rule.type = item.value("type", "");
                rule.value = item.value("value", "");
                rule.direction = item.value("direction", "");
                rule.rate = item.value("rate", "");
                rule.classId = item.value("classId", 10);
                if (!rule.id.empty() && !rule.value.empty() && !rule.rate.empty()) {
                    rules.push_back(rule);
                    if (rule.classId >= nextClassId) {
                        nextClassId = rule.classId + 1;
                    }
                }
            }
        }
        Logger::log("QoS: Config loaded successfully.", Logger::INFO);
    } catch (const std::exception& e) {
        Logger::log("QoS: Error loading config: " + std::string(e.what()), Logger::ERROR);
    }
    file.close();
}

void QosManager::saveRulesConfig() {
    json j;
    json rulesList = json::array();
    {
        std::lock_guard<std::mutex> lock(qosMutex);
        for (const auto& rule : rules) {
            json item;
            item["id"] = rule.id;
            item["type"] = rule.type;
            item["value"] = rule.value;
            item["direction"] = rule.direction;
            item["rate"] = rule.rate;
            item["classId"] = rule.classId;
            rulesList.push_back(item);
        }
    }
    j["rules"] = rulesList;

    std::ofstream file(QOS_RULES_FILE);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
        Logger::log("QoS: Config saved.", Logger::INFO);
    } else {
        Logger::log("QoS: Failed to save config.", Logger::ERROR);
    }
}

bool QosManager::addRule(const std::string& type, const std::string& value, const std::string& direction, const std::string& rate) {
    if (value.empty() || rate.empty() || (type != "ip" && type != "port")) {
        Logger::log("QoS: Invalid rule parameters for add.", Logger::ERROR);
        return false;
    }

    std::lock_guard<std::mutex> lock(qosMutex);
    
    QosRule rule;
    rule.classId = nextClassId++;
    rule.id = "qos_rule_" + std::to_string(rule.classId);
    rule.type = type;
    rule.value = value;
    rule.direction = direction;
    rule.rate = rate;
    
    rules.push_back(rule);
    Logger::log("QoS: Adding rules list item: " + rule.id, Logger::INFO);

    // Apply the rules immediately on system
    qosMutex.unlock();
    reapplyAllRules();
    qosMutex.lock();

    saveRulesConfig();
    return true;
}

bool QosManager::removeRule(const std::string& id) {
    std::lock_guard<std::mutex> lock(qosMutex);
    auto it = std::find_if(rules.begin(), rules.end(), [&](const QosRule& r) { return r.id == id; });
    if (it == rules.end()) {
        Logger::log("QoS: Rule not found: " + id, Logger::WARNING);
        return false;
    }

    rules.erase(it);
    Logger::log("QoS: Removed rule " + id, Logger::INFO);

    // Apply change by resetting and rebuilding all active rules
    qosMutex.unlock();
    reapplyAllRules();
    qosMutex.lock();

    saveRulesConfig();
    return true;
}

std::vector<QosRule> QosManager::getRules() {
    std::lock_guard<std::mutex> lock(qosMutex);
    return rules;
}

void QosManager::clearRules() {
    {
        std::lock_guard<std::mutex> lock(qosMutex);
        rules.clear();
        nextClassId = 11;
    }
    reapplyAllRules();
    saveRulesConfig();
}

void QosManager::reapplyAllRules() {
    // Reset system queues first
    initQdisc();

    std::lock_guard<std::mutex> lock(qosMutex);
    for (const auto& rule : rules) {
        Logger::log("QoS: Reapplying system tc rule for " + rule.id, Logger::INFO);
        
        // Add class for this rule
        std::string cmd = "tc class add dev " + interfaceName + " parent 1: classid 1:" + std::to_string(rule.classId) + 
                          " htb rate " + rule.rate + " ceil " + rule.rate + " 2>&1";
        std::string out = executeSystemCommand(cmd);
        Logger::log("QoS: Class rule execution output: " + out, Logger::DEBUG);

        // Add filter mapping traffic to this class
        if (rule.type == "ip") {
            std::string dirKeyword = (rule.direction == "dst") ? "dst" : "src";
            cmd = "tc filter add dev " + interfaceName + " protocol ip parent 1:0 prio 1 u32 match ip " + dirKeyword + 
                  " " + rule.value + " flowid 1:" + std::to_string(rule.classId) + " 2>&1";
            out = executeSystemCommand(cmd);
            Logger::log("QoS: Filter rule execution output: " + out, Logger::DEBUG);
        } else if (rule.type == "port") {
            // Apply shaper on both destination and source port
            cmd = "tc filter add dev " + interfaceName + " protocol ip parent 1:0 prio 1 u32 match ip dport " + 
                  rule.value + " 0xffff flowid 1:" + std::to_string(rule.classId) + " 2>&1";
            executeSystemCommand(cmd);
            cmd = "tc filter add dev " + interfaceName + " protocol ip parent 1:0 prio 1 u32 match ip sport " + 
                  rule.value + " 0xffff flowid 1:" + std::to_string(rule.classId) + " 2>&1";
            executeSystemCommand(cmd);
        }
    }
}
