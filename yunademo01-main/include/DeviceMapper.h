#ifndef DEVICE_MAPPER_H
#define DEVICE_MAPPER_H

#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>

struct NetworkDevice {
    std::string ip;
    std::string mac;
    std::string hostname;
    std::string interface;
    bool isOnline = false;
};

class DeviceMapper {
private:
    std::string targetInterface;
    std::vector<NetworkDevice> devices;
    std::mutex mapperMutex;
    std::thread scanThread;
    std::atomic<bool> running;
    int scanIntervalSeconds;

    void runScanLoop();
    std::string getHostnameFromIp(const std::string& ip);
    std::string executeSystemCommand(const std::string& cmd);

public:
    DeviceMapper(const std::string& interface);
    ~DeviceMapper();

    void scanNow();
    std::vector<NetworkDevice> getDevices();
    
    void startAutoScan(int intervalSeconds = 30);
    void stopAutoScan();
};

#endif // DEVICE_MAPPER_H
