#ifndef THREAT_INTEL_SYNCHRONIZER_H
#define THREAT_INTEL_SYNCHRONIZER_H

#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <thread>
#include <atomic>

class ThreatIntelSynchronizer {
private:
    std::set<std::string> synchronizedIPs;
    std::vector<std::string> feedUrls;
    std::mutex syncMutex;
    std::thread syncThread;
    std::atomic<bool> running;
    std::atomic<bool> forceSync;
    int syncIntervalHours;
    std::string databaseFile;

    void loadSynchronizedIPs();
    void saveSynchronizedIPs();
    void loadFeedUrls();
    void saveFeedUrls();
    void runSyncLoop();
    bool downloadFeed(const std::string& url, std::string& response);
    void parseAndMergeIPs(const std::string& data);

public:
    ThreatIntelSynchronizer();
    ~ThreatIntelSynchronizer();

    bool addFeedUrl(const std::string& url);
    bool removeFeedUrl(const std::string& url);
    std::vector<std::string> getFeedUrls();

    bool isThreatIP(const std::string& ip);
    void triggerSync();
    void syncNow();
    size_t getThreatIPCount();
    
    void startAutoSync(int intervalHours = 24);
    void stopAutoSync();
};

#endif // THREAT_INTEL_SYNCHRONIZER_H
