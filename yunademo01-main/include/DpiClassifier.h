#ifndef DPI_CLASSIFIER_H
#define DPI_CLASSIFIER_H

#include <string>
#include <vector>
#include <map>
#include <mutex>

struct ProtocolStats {
    std::string name;
    unsigned long long packetCount = 0;
    unsigned long long totalBytes = 0;
};

class DpiClassifier {
private:
    std::map<std::string, ProtocolStats> stats;
    std::mutex dpiMutex;
    std::string statsFilePath;

    void loadStats();
    void saveStats();
    bool parseTlsClientHello(const std::string& payload, std::string& sni);

public:
    DpiClassifier();
    ~DpiClassifier();

    std::string classifyPayload(const std::string& payload, int destPort, std::string& detail);
    void recordTraffic(const std::string& protocol, size_t bytes);
    std::map<std::string, ProtocolStats> getStats();
    void clearStats();
};

#endif // DPI_CLASSIFIER_H
