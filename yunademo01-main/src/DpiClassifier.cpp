#include "DpiClassifier.h"
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

using json = nlohmann::json;

#define DPI_STATS_FILE "dpi_stats.json"

DpiClassifier::DpiClassifier() : statsFilePath(DPI_STATS_FILE) {
    loadStats();
}

DpiClassifier::~DpiClassifier() {
    saveStats();
}

void DpiClassifier::loadStats() {
    std::ifstream file(statsFilePath);
    if (!file.is_open()) return;
    json j;
    try {
        file >> j;
        if (j.contains("stats") && j["stats"].is_object()) {
            stats.clear();
            for (auto it = j["stats"].begin(); it != j["stats"].end(); ++it) {
                ProtocolStats ps;
                ps.name = it.key();
                ps.packetCount = it.value().value("packetCount", 0ULL);
                ps.totalBytes = it.value().value("totalBytes", 0ULL);
                stats[it.key()] = ps;
            }
        }
    } catch (...) {}
    file.close();
}

void DpiClassifier::saveStats() {
    json j;
    json statsObj = json::object();
    for (const auto& pair : stats) {
        json item;
        item["packetCount"] = pair.second.packetCount;
        item["totalBytes"] = pair.second.totalBytes;
        statsObj[pair.first] = item;
    }
    j["stats"] = statsObj;
    std::ofstream file(statsFilePath);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
    }
}

// Safely parses Server Name Indication (SNI) from TLS Client Hello bytes
bool DpiClassifier::parseTlsClientHello(const std::string& payload, std::string& sni) {
    size_t size = payload.size();
    if (size < 47) return false;

    const unsigned char* data = reinterpret_cast<const unsigned char*>(payload.data());
    
    // Index tracking
    size_t idx = 5; // Start of Handshake Protocol

    // Handshake Type must be Client Hello (0x01)
    if (data[idx] != 0x01) return false;
    
    // Skip Handshake Type (1) + Length (3) + Version (2) + Random (32)
    idx += 1 + 3 + 2 + 32;
    if (idx >= size) return false;

    // Session ID
    size_t sessLen = data[idx];
    idx += 1 + sessLen;
    if (idx + 2 >= size) return false;

    // Cipher Suites
    size_t cipherLen = (data[idx] << 8) | data[idx + 1];
    idx += 2 + cipherLen;
    if (idx >= size) return false;

    // Compression Methods
    size_t compLen = data[idx];
    idx += 1 + compLen;
    if (idx + 2 >= size) return false;

    // Extensions Length
    size_t extLen = (data[idx] << 8) | data[idx + 1];
    idx += 2;
    size_t extEnd = idx + extLen;
    if (extEnd > size) return false;

    // Loop through extensions
    while (idx + 4 <= extEnd) {
        unsigned short type = (data[idx] << 8) | data[idx + 1];
        unsigned short len = (data[idx + 2] << 8) | data[idx + 3];
        idx += 4;
        
        if (idx + len > extEnd) return false;

        // SNI Extension Type is 0x0000
        if (type == 0x0000) {
            size_t sIdx = idx;
            if (sIdx + 2 > idx + len) return false;
            unsigned short listLen = (data[sIdx] << 8) | data[sIdx + 1];
            sIdx += 2;

            if (sIdx + listLen > idx + len) return false;

            while (sIdx + 3 <= idx + len) {
                unsigned char nameType = data[sIdx];
                unsigned short nameLen = (data[sIdx + 1] << 8) | data[sIdx + 2];
                sIdx += 3;

                if (sIdx + nameLen > idx + len) return false;

                // Name Type 0 is Host Name
                if (nameType == 0x00) {
                    sni = std::string(reinterpret_cast<const char*>(data + sIdx), nameLen);
                    return true;
                }
                sIdx += nameLen;
            }
        }
        idx += len;
    }
    return false;
}

std::string DpiClassifier::classifyPayload(const std::string& payload, int destPort, std::string& detail) {
    if (payload.empty()) {
        // Port-based fallback if payload is empty
        detail = "No payload data (Port " + std::to_string(destPort) + ")";
        if (destPort == 80 || destPort == 8080) return "HTTP";
        if (destPort == 443) return "TLS/SSL";
        if (destPort == 22) return "SSH";
        if (destPort == 53) return "DNS";
        if (destPort == 21) return "FTP";
        if (destPort == 23) return "Telnet";
        return "Unknown";
    }

    size_t len = payload.size();
    const unsigned char* data = reinterpret_cast<const unsigned char*>(payload.data());

    // 1. TLS/SSL Check
    // Starts with Content Type Handshake (0x16) and TLS Version (0x03)
    if (len >= 5 && data[0] == 0x16 && data[1] == 0x03) {
        std::string sni = "";
        if (parseTlsClientHello(payload, sni)) {
            detail = "SNI: " + sni;
        } else {
            detail = "Encrypted TLS Handshake";
        }
        return "TLS/SSL";
    }
    // Starts with Application Data (0x17) and TLS Version (0x03)
    if (len >= 5 && data[0] == 0x17 && data[1] == 0x03) {
        detail = "Encrypted Application Data";
        return "TLS/SSL";
    }

    // 2. HTTP Check
    // Check for HTTP methods at the start of packet
    std::vector<std::string> httpMethods = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH "};
    bool looksLikeHttp = false;
    for (const auto& method : httpMethods) {
        if (payload.rfind(method, 0) == 0) {
            looksLikeHttp = true;
            break;
        }
    }
    if (looksLikeHttp && payload.find("HTTP/") != std::string::npos) {
        // Extract Host Header
        size_t hostPos = payload.find("Host: ");
        if (hostPos == std::string::npos) {
            hostPos = payload.find("host: ");
        }
        if (hostPos != std::string::npos) {
            size_t valStart = hostPos + 6;
            size_t valEnd = payload.find("\r\n", valStart);
            if (valEnd != std::string::npos) {
                detail = "Host: " + payload.substr(valStart, valEnd - valStart);
                return "HTTP";
            }
        }
        detail = "HTTP Request";
        return "HTTP";
    }

    // 3. SSH Check
    if (payload.rfind("SSH-", 0) == 0) {
        size_t bannerEnd = payload.find("\r\n");
        if (bannerEnd == std::string::npos) {
            bannerEnd = payload.find("\n");
        }
        if (bannerEnd != std::string::npos) {
            detail = "Banner: " + payload.substr(0, bannerEnd);
        } else {
            detail = "SSH Protocol Exchange";
        }
        return "SSH";
    }

    // Port-based classification fallback if signature did not match but payload exists
    if (destPort == 80 || destPort == 8080) {
        detail = "Fallback Port-80/8080 HTTP";
        return "HTTP";
    }
    if (destPort == 443) {
        detail = "Fallback Port-443 TLS/SSL";
        return "TLS/SSL";
    }
    if (destPort == 22) {
        detail = "Fallback Port-22 SSH";
        return "SSH";
    }
    if (destPort == 53) {
        detail = "Fallback Port-53 DNS";
        return "DNS";
    }

    detail = "Raw Unclassified Payload (" + std::to_string(len) + " bytes)";
    return "Unknown";
}

void DpiClassifier::recordTraffic(const std::string& protocol, size_t bytes) {
    std::lock_guard<std::mutex> lock(dpiMutex);
    auto& ps = stats[protocol];
    ps.name = protocol;
    ps.packetCount++;
    ps.totalBytes += bytes;
    saveStats();
}

std::map<std::string, ProtocolStats> DpiClassifier::getStats() {
    std::lock_guard<std::mutex> lock(dpiMutex);
    return stats;
}

void DpiClassifier::clearStats() {
    std::lock_guard<std::mutex> lock(dpiMutex);
    stats.clear();
    saveStats();
}
