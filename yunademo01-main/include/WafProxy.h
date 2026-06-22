#ifndef WAF_PROXY_H
#define WAF_PROXY_H

#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <map>

class FirewallManager;

struct WafRule {
    int id;
    std::string pattern;
    std::string attackType; // "SQL Injection", "XSS", "Path Traversal", etc.
    bool enabled = true;
};

struct WafLogRecord {
    std::string timestamp;
    std::string clientIp;
    std::string method;
    std::string url;
    std::string attackType;
    std::string matchedPattern;
    bool blocked;
};

class WafProxy {
private:
    FirewallManager* manager;
    std::thread serverThread;
    std::atomic<bool> running;
    int listenPort;
    std::string backendHost;
    int backendPort;
    int serverSocket;
    std::string rulesFilePath;
    std::mutex wafMutex;

    std::vector<WafRule> customRules;
    std::vector<WafLogRecord> logs;

    // Statistics
    unsigned long long totalRequests;
    unsigned long long blockedRequests;
    std::map<std::string, unsigned long long> attackStats;

    void runServerLoop();
    void handleProxyConnection(int clientSocket, const std::string& clientIp);
    std::string getTimestamp();
    void loadRules();
    void saveRules();

public:
    explicit WafProxy(FirewallManager* mgr);
    ~WafProxy();

    bool startServer(int port = 8080, const std::string& backendHost = "127.0.0.1", int backendPort = 8081);
    void stopServer();
    bool isRunning() const { return running.load(); }

    // WAF Inspection core logic
    bool inspectRequest(const std::string& request, std::string& attackType, std::string& matchedPattern);

    // Rule management
    bool addRule(const std::string& pattern, const std::string& attackType);
    bool removeRule(int id);
    std::vector<WafRule> getRules();

    // Logs & Stats
    std::vector<WafLogRecord> getLogs();
    void clearLogs();
    unsigned long long getTotalRequests();
    unsigned long long getBlockedRequests();
    std::map<std::string, unsigned long long> getStats();
};

#endif // WAF_PROXY_H
