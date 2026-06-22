#include "ThreatIntelligenceIntegrator.h"
#include "Logger.h"
#include <nlohmann/json.hpp>

ThreatIntelligenceIntegrator::ThreatIntelligenceIntegrator(const std::string& url) : apiUrl(url) {
    curl = curl_easy_init();
    if (!curl) {
        Logger::log("Failed to initialize CURL for threat intel.", Logger::ERROR);
    }
}

ThreatIntelligenceIntegrator::~ThreatIntelligenceIntegrator() {
    if (curl) {
        curl_easy_cleanup(curl);
    }
}

bool ThreatIntelligenceIntegrator::isThreatIP(const std::string& ip) {
    auto now = std::chrono::system_clock::now();
    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        auto it = threatCache.find(ip);
        if (it != threatCache.end()) {
            if (now < it->second.expiry) {
                Logger::log("Threat cache hit for IP: " + ip + " (Threat: " + (it->second.isThreat ? "Yes" : "No") + ")", Logger::DEBUG);
                return it->second.isThreat;
            }
        }
    }

    bool isThreat = false;
    if (curl) {
        std::string url = apiUrl + "?ip=" + ip;
        std::string responseString;
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L); // 2 second timeout
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1L); // 1 second connection timeout
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
            auto* str = static_cast<std::string*>(userdata);
            str->append(ptr, size * nmemb);
            return size * nmemb;
        });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);

        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            try {
                auto j = nlohmann::json::parse(responseString);
                if (j.contains("is_threat") && j["is_threat"].is_boolean()) {
                    isThreat = j["is_threat"].get<bool>();
                } else if (j.contains("reputation") && j["reputation"].is_string()) {
                    isThreat = (j["reputation"].get<std::string>() == "malicious");
                }
                Logger::log("Threat intel query succeeded for IP " + ip + ": " + (isThreat ? "Threat" : "Clean"), Logger::INFO);
            } catch (...) {
                Logger::log("Threat intel returned invalid response JSON for IP " + ip, Logger::WARNING);
            }
        } else {
            Logger::log("Threat intel query failed for IP " + ip + ": " + std::string(curl_easy_strerror(res)), Logger::WARNING);
        }
    }

    {
        std::lock_guard<std::mutex> lock(cacheMutex);
        CacheEntry entry;
        entry.isThreat = isThreat;
        entry.expiry = now + std::chrono::hours(1);
        threatCache[ip] = entry;
    }

    return isThreat;
}
