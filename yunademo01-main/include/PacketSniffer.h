#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include "Common.h"
#include <pcap/pcap.h>
#include <string>
#include <thread>
#include <atomic>

class FirewallManager;

class PacketSniffer {
private:
    pcap_t* handle;
    std::string device;
    std::thread sniffThread;
    FirewallManager* manager;
    std::atomic<bool> sniffing;

public:
    PacketSniffer(const std::string& dev, FirewallManager* mgr);
    ~PacketSniffer();
    bool start();
    void stop();
    static void packetCallback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
};

#endif // PACKET_SNIFFER_H
