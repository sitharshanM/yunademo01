#include "WafProxy.h"
#include "FirewallManager.h"
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <iostream>
#include <ctime>
#include <algorithm>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close_socket(s) closesocket(s)
    #define read_socket(s, b, l) recv(s, b, l, 0)
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/select.h>
    #define close_socket(s) ::close(s)
    #define read_socket(s, b, l) ::read(s, b, l)
#endif

using json = nlohmann::json;

#define WAF_RULES_FILE "waf_rules.json"

WafProxy::WafProxy(FirewallManager* mgr)
    : manager(mgr), running(false), listenPort(8080), backendHost("127.0.0.1"), backendPort(8081),
      serverSocket(-1), rulesFilePath(WAF_RULES_FILE), totalRequests(0), blockedRequests(0) {
    
    // Initialize stats categories
    attackStats["SQL Injection"] = 0;
    attackStats["Cross-Site Scripting"] = 0;
    attackStats["Path Traversal"] = 0;
    attackStats["Command Injection"] = 0;
    attackStats["Custom Pattern"] = 0;

    loadRules();
}

WafProxy::~WafProxy() {
    stopServer();
}

std::string WafProxy::getTimestamp() {
    std::time_t now = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buf);
}

void WafProxy::loadRules() {
    std::ifstream file(rulesFilePath);
    if (!file.is_open()) return;
    json j;
    try {
        file >> j;
        if (j.contains("rules") && j["rules"].is_array()) {
            customRules.clear();
            for (const auto& item : j["rules"]) {
                WafRule r;
                r.id = item.value("id", 0);
                r.pattern = item.value("pattern", "");
                r.attackType = item.value("attackType", "Custom Pattern");
                r.enabled = item.value("enabled", true);
                customRules.push_back(r);
            }
        }
    } catch (...) {}
    file.close();
}

void WafProxy::saveRules() {
    json j;
    json ruleList = json::array();
    for (const auto& r : customRules) {
        json item;
        item["id"] = r.id;
        item["pattern"] = r.pattern;
        item["attackType"] = r.attackType;
        item["enabled"] = r.enabled;
        ruleList.push_back(item);
    }
    j["rules"] = ruleList;
    std::ofstream file(rulesFilePath);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
    }
}

bool WafProxy::startServer(int port, const std::string& backend, int bPort) {
    if (running.load()) return true;
    listenPort = port;
    backendHost = backend;
    backendPort = bPort;
    running = true;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        Logger::log("WAF Proxy: WSAStartup failed.", Logger::ERROR);
        running = false;
        return false;
    }
#endif

    serverThread = std::thread(&WafProxy::runServerLoop, this);
    Logger::log("WAF Proxy: Server started on port " + std::to_string(port) + 
                " -> forwarding to " + backend + ":" + std::to_string(bPort), Logger::INFO);
    return true;
}

void WafProxy::stopServer() {
    if (!running.load()) return;
    running = false;

    if (serverSocket >= 0) {
        close_socket(serverSocket);
        serverSocket = -1;
    }

    if (serverThread.joinable()) {
        serverThread.join();
    }

#ifdef _WIN32
    WSACleanup();
#endif

    Logger::log("WAF Proxy: Server stopped.", Logger::INFO);
}

void WafProxy::runServerLoop() {
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        Logger::log("WAF Proxy: Failed to create socket.", Logger::ERROR);
        running = false;
        return;
    }

    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(listenPort);

    if (bind(serverSocket, (struct sockaddr*)&address, sizeof(address)) < 0) {
        Logger::log("WAF Proxy: Bind failed on port " + std::to_string(listenPort), Logger::ERROR);
        close_socket(serverSocket);
        serverSocket = -1;
        running = false;
        return;
    }

    if (listen(serverSocket, 20) < 0) {
        Logger::log("WAF Proxy: Listen failed.", Logger::ERROR);
        close_socket(serverSocket);
        serverSocket = -1;
        running = false;
        return;
    }

    while (running.load()) {
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(serverSocket, &readFds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int selectRet = select(serverSocket + 1, &readFds, nullptr, nullptr, &tv);
        if (selectRet > 0) {
            struct sockaddr_in clientAddr;
#ifdef _WIN32
            int addrLen = sizeof(clientAddr);
#else
            socklen_t addrLen = sizeof(clientAddr);
#endif
            int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrLen);
            if (clientSocket >= 0) {
                char ipBuf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &clientAddr.sin_addr, ipBuf, sizeof(ipBuf));
                std::string clientIp = ipBuf;

                std::thread(&WafProxy::handleProxyConnection, this, clientSocket, clientIp).detach();
            }
        }
    }

    if (serverSocket >= 0) {
        close_socket(serverSocket);
        serverSocket = -1;
    }
}

bool WafProxy::inspectRequest(const std::string& request, std::string& attackType, std::string& matchedPattern) {
    std::string reqLower = request;
    std::transform(reqLower.begin(), reqLower.end(), reqLower.begin(), ::tolower);

    // Built-in SQL Injection (SQLi) Signatures
    std::vector<std::string> sqliSigs = {
        "' or '1'='1",
        "\" or \"1\"=\"1",
        "union select",
        "select ",
        "insert into",
        "delete from",
        "drop table",
        "union all select",
        "admin'--",
        "admin' /*",
        "'--"
    };
    for (const auto& sig : sqliSigs) {
        if (reqLower.find(sig) != std::string::npos) {
            attackType = "SQL Injection";
            matchedPattern = sig;
            return true;
        }
    }

    // Built-in Cross-Site Scripting (XSS) Signatures
    std::vector<std::string> xssSigs = {
        "<script>",
        "</script>",
        "javascript:",
        "onerror=",
        "onload=",
        "onclick=",
        "alert(",
        "<img src",
        "src=javascript:",
        "eval("
    };
    for (const auto& sig : xssSigs) {
        if (reqLower.find(sig) != std::string::npos) {
            attackType = "Cross-Site Scripting";
            matchedPattern = sig;
            return true;
        }
    }

    // Built-in Path Traversal Signatures
    std::vector<std::string> traversalSigs = {
        "../",
        "..\\",
        "/etc/passwd",
        "/etc/shadow",
        "\\windows\\win.ini",
        "\\winnt\\win.ini",
        "boot.ini"
    };
    for (const auto& sig : traversalSigs) {
        if (reqLower.find(sig) != std::string::npos) {
            attackType = "Path Traversal";
            matchedPattern = sig;
            return true;
        }
    }

    // Built-in Command Injection Signatures
    std::vector<std::string> cmdSigs = {
        "; rm -rf",
        "| rm -rf",
        "& rm -rf",
        "; wget ",
        "; curl ",
        "| sh",
        "| bash",
        "/bin/sh",
        "/bin/bash"
    };
    for (const auto& sig : cmdSigs) {
        if (reqLower.find(sig) != std::string::npos) {
            attackType = "Command Injection";
            matchedPattern = sig;
            return true;
        }
    }

    // Custom user-defined rules
    std::lock_guard<std::mutex> lock(wafMutex);
    for (const auto& rule : customRules) {
        if (rule.enabled && !rule.pattern.empty()) {
            std::string patLower = rule.pattern;
            std::transform(patLower.begin(), patLower.end(), patLower.begin(), ::tolower);
            if (reqLower.find(patLower) != std::string::npos) {
                attackType = rule.attackType;
                matchedPattern = rule.pattern;
                return true;
            }
        }
    }

    return false;
}

void WafProxy::handleProxyConnection(int clientSocket, const std::string& clientIp) {
    char buffer[4096] = {0};
    int bytesRead = read_socket(clientSocket, buffer, sizeof(buffer) - 1);
    if (bytesRead <= 0) {
        close_socket(clientSocket);
        return;
    }

    std::string request(buffer, bytesRead);
    std::string method = "UNKNOWN";
    std::string url = "/";
    
    // Parse standard HTTP method and URL
    size_t firstSpace = request.find(' ');
    if (firstSpace != std::string::npos) {
        method = request.substr(0, firstSpace);
        size_t secondSpace = request.find(' ', firstSpace + 1);
        if (secondSpace != std::string::npos) {
            url = request.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        }
    }

    // URL decode helper (simplistic)
    std::string decodedUrl = url;
    std::replace(decodedUrl.begin(), decodedUrl.end(), '+', ' ');
    // Decode basic hex entities
    std::string decodedRequest = request;
    // Replace URL encoded characters (e.g. %20 -> ' ', %3C -> '<', %3E -> '>')
    for (size_t i = 0; i < decodedRequest.size(); ++i) {
        if (decodedRequest[i] == '%' && i + 2 < decodedRequest.size()) {
            std::string hex = decodedRequest.substr(i + 1, 2);
            char chr = (char)std::strtol(hex.c_str(), nullptr, 16);
            if (chr > 0) {
                decodedRequest.replace(i, 3, 1, chr);
            }
        }
    }

    // Increment request stats
    {
        std::lock_guard<std::mutex> lock(wafMutex);
        totalRequests++;
    }

    std::string attackType = "";
    std::string matchedPattern = "";
    bool hasViolation = inspectRequest(decodedRequest, attackType, matchedPattern);

    if (hasViolation) {
        // Block Request and Log
        {
            std::lock_guard<std::mutex> lock(wafMutex);
            blockedRequests++;
            attackStats[attackType]++;

            WafLogRecord record;
            record.timestamp = getTimestamp();
            record.clientIp = clientIp;
            record.method = method;
            record.url = url;
            record.attackType = attackType;
            record.matchedPattern = matchedPattern;
            record.blocked = true;

            logs.push_back(record);
            if (logs.size() > 100) {
                logs.erase(logs.begin());
            }
        }

        // Notify FirewallManager of the threat
        manager->respondToThreat(clientIp);
        manager->sendNotification("WAF Attack Blocked", "Intercepted " + attackType + " from " + clientIp);
        Logger::log("WAF Proxy: Blocked request from " + clientIp + " containing " + attackType + " (" + matchedPattern + ")", Logger::WARNING);

        // Serve 403 Block Page
        std::string htmlBody = "<html><head><title>YUNA WAF - Request Blocked</title>";
        htmlBody += "<style>";
        htmlBody += "body { font-family:'Segoe UI',Arial,sans-serif; background-color: #1a1a1a; color: #fff; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }";
        htmlBody += ".card { background: #2d2d2d; padding: 40px; border-radius: 8px; border-top: 5px solid #e43f5a; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 100%; max-width: 550px; text-align: left; }";
        htmlBody += "h2 { color: #e43f5a; margin-top: 0; display:flex; align-items:center; }";
        htmlBody += "h2 span { font-size: 24px; margin-right: 10px; }";
        htmlBody += ".meta-box { background: #222; padding: 15px; border-radius: 4px; font-family: monospace; font-size: 13px; margin: 20px 0; color: #ccc; }";
        htmlBody += ".meta-item { margin-bottom: 5px; }";
        htmlBody += ".meta-item b { color: #e43f5a; }";
        htmlBody += "p { line-height: 1.6; color: #aaa; }";
        htmlBody += "a.btn { display: inline-block; background-color: #e43f5a; color: white; border: none; padding: 10px 20px; border-radius: 4px; text-decoration: none; font-weight: bold; cursor: pointer; transition: background 0.3s; margin-top: 10px; }";
        htmlBody += "a.btn:hover { background-color: #ca3e52; }";
        htmlBody += "</style></head><body>";
        htmlBody += "<div class='card'><h2><span>&#9888;</span> Security Violation Detected</h2>";
        htmlBody += "<p>Your HTTP request was intercepted by the **YUNA Web Application Firewall (WAF)** because it triggered security inspection signatures.</p>";
        htmlBody += "<div class='meta-box'>";
        htmlBody += "<div class='meta-item'><b>Violator IP:</b> " + clientIp + "</div>";
        htmlBody += "<div class='meta-item'><b>Detection Class:</b> " + attackType + "</div>";
        htmlBody += "<div class='meta-item'><b>Signature Match:</b> " + matchedPattern + "</div>";
        htmlBody += "<div class='meta-item'><b>Request URI:</b> " + url + "</div>";
        htmlBody += "<div class='meta-item'><b>Firewall Action:</b> Drop & Block Host</div>";
        htmlBody += "</div>";
        htmlBody += "<p>If you believe this is an administrative error, please contact the security systems engineer.</p>";
        htmlBody += "<a class='btn' href='javascript:history.back()'>Go Back</a></div></body></html>";

        std::string response = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: " + 
                              std::to_string(htmlBody.size()) + "\r\nConnection: close\r\n\r\n" + htmlBody;
        send(clientSocket, response.c_str(), response.size(), 0);
        close_socket(clientSocket);
        return;
    }

    // Forward clean request to the backend server
    int backendSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (backendSocket < 0) {
        close_socket(clientSocket);
        return;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(backendPort);
    
    int ptonRet = inet_pton(AF_INET, backendHost.c_str(), &serv_addr.sin_addr);
    if (ptonRet <= 0) {
        close_socket(backendSocket);
        close_socket(clientSocket);
        return;
    }

    int connectRet = connect(backendSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (connectRet < 0) {
        // Backend offline response
        std::string htmlBody = "<html><head><title>502 Bad Gateway</title></head><body><h1 style='text-align:center;font-family:sans-serif;'>502 Bad Gateway</h1><p style='text-align:center;'>YUNA Reverse Proxy: Unable to connect to the backend server.</p></body></html>";
        std::string response = "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html\r\nContent-Length: " + 
                              std::to_string(htmlBody.size()) + "\r\nConnection: close\r\n\r\n" + htmlBody;
        send(clientSocket, response.c_str(), response.size(), 0);
        close_socket(backendSocket);
        close_socket(clientSocket);
        return;
    }

    // Forward request to backend
    send(backendSocket, request.c_str(), request.size(), 0);

    // Read response from backend and write back to client
    char respBuf[4096];
    int bytesReadFromBackend;
    while ((bytesReadFromBackend = read_socket(backendSocket, respBuf, sizeof(respBuf))) > 0) {
        send(clientSocket, respBuf, bytesReadFromBackend, 0);
    }

    // Log Successful Clean Proxying
    {
        std::lock_guard<std::mutex> lock(wafMutex);
        WafLogRecord record;
        record.timestamp = getTimestamp();
        record.clientIp = clientIp;
        record.method = method;
        record.url = url;
        record.attackType = "None";
        record.matchedPattern = "-";
        record.blocked = false;

        logs.push_back(record);
        if (logs.size() > 100) {
            logs.erase(logs.begin());
        }
    }

    close_socket(backendSocket);
    close_socket(clientSocket);
}

bool WafProxy::addRule(const std::string& pattern, const std::string& attackType) {
    if (pattern.empty()) return false;
    std::lock_guard<std::mutex> lock(wafMutex);
    
    // Check duplicates
    for (const auto& rule : customRules) {
        if (rule.pattern == pattern) return false;
    }

    int nextId = 1;
    if (!customRules.empty()) {
        nextId = customRules.back().id + 1;
    }

    WafRule r;
    r.id = nextId;
    r.pattern = pattern;
    r.attackType = attackType.empty() ? "Custom Pattern" : attackType;
    r.enabled = true;

    customRules.push_back(r);
    saveRules();
    Logger::log("WAF Proxy: Added custom rule pattern: " + pattern, Logger::INFO);
    return true;
}

bool WafProxy::removeRule(int id) {
    std::lock_guard<std::mutex> lock(wafMutex);
    auto it = std::remove_if(customRules.begin(), customRules.end(), [id](const WafRule& r) {
        return r.id == id;
    });

    if (it != customRules.end()) {
        customRules.erase(it, customRules.end());
        saveRules();
        Logger::log("WAF Proxy: Removed custom rule ID: " + std::to_string(id), Logger::INFO);
        return true;
    }
    return false;
}

std::vector<WafRule> WafProxy::getRules() {
    std::lock_guard<std::mutex> lock(wafMutex);
    return customRules;
}

std::vector<WafLogRecord> WafProxy::getLogs() {
    std::lock_guard<std::mutex> lock(wafMutex);
    return logs;
}

void WafProxy::clearLogs() {
    std::lock_guard<std::mutex> lock(wafMutex);
    logs.clear();
}

unsigned long long WafProxy::getTotalRequests() {
    std::lock_guard<std::mutex> lock(wafMutex);
    return totalRequests;
}

unsigned long long WafProxy::getBlockedRequests() {
    std::lock_guard<std::mutex> lock(wafMutex);
    return blockedRequests;
}

std::map<std::string, unsigned long long> WafProxy::getStats() {
    std::lock_guard<std::mutex> lock(wafMutex);
    return attackStats;
}
