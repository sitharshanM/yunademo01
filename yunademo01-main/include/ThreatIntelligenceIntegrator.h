#ifndef THREAT_INTELLIGENCE_INTEGRATOR_H
#define THREAT_INTELLIGENCE_INTEGRATOR_H

#include "Common.h"
#include <curl/curl.h>
#include <string>
#include <unordered_map>
#include <chrono>
#include <mutex>

class ThreatIntelligenceIntegrator {
private:
    struct CacheEntry {
        bool isThreat;
        std::chrono::system_clock::time_point expiry;
    };

    CURL* curl;
    std::string apiUrl;
    std::unordered_map<std::string, CacheEntry> threatCache;
    std::mutex cacheMutex;

public:
    ThreatIntelligenceIntegrator(const std::string& url);
    ~ThreatIntelligenceIntegrator();
    bool isThreatIP(const std::string& ip);
};

#endif // THREAT_INTELLIGENCE_INTEGRATOR_H
