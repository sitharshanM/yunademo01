#include "PacketSniffer.h"
#include "FirewallManager.h"
#include "Logger.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cmath>

static double calculateEntropy(const u_char *data, int size) {
    if (size <= 0 || !data) return 0.0;
    int counts[256] = {0};
    for (int i = 0; i < size; ++i) {
        counts[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] > 0) {
            double p = static_cast<double>(counts[i]) / size;
            entropy -= p * (std::log(p) / std::log(2.0));
        }
    }
    return entropy;
}

static std::string parseDNSQuery(const u_char *dnsPayload, int payloadLen) {
    if (payloadLen < 12) return "";
    int offset = 12; // Skip 12-byte DNS header
    std::string domain;
    while (offset < payloadLen) {
        int len = dnsPayload[offset];
        if (len == 0) break;
        if ((len & 0xC0) == 0xC0) break; // Pointer compression (uncommon in query names, safety check)
        if (offset + 1 + len > payloadLen) return ""; // Out-of-bounds safety
        if (!domain.empty()) domain += ".";
        for (int i = 0; i < len; ++i) {
            domain += static_cast<char>(dnsPayload[offset + 1 + i]);
        }
        offset += 1 + len;
    }
    return domain;
}

PacketSniffer::PacketSniffer(const std::string& dev, FirewallManager* mgr)
    : handle(nullptr), device(dev), manager(mgr), sniffing(false) {}

PacketSniffer::~PacketSniffer() {
    stop();
}

bool PacketSniffer::start() {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        Logger::log("Failed to open device " + device + ": " + errbuf, Logger::ERROR);
        return false;
    }
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(handle, &fp) == -1) {
        Logger::log("Failed to set packet filter.", Logger::ERROR);
        pcap_close(handle);
        return false;
    }
    sniffing = true;
    sniffThread = std::thread([this]() {
        pcap_loop(handle, 0, packetCallback, reinterpret_cast<u_char*>(manager));
    });
    Logger::log("Packet sniffing started on " + device, Logger::INFO);
    return true;
}

void PacketSniffer::stop() {
    if (sniffing.load()) {
        pcap_breakloop(handle);
        if (sniffThread.joinable()) sniffThread.join();
        pcap_close(handle);
        sniffing = false;
        Logger::log("Packet sniffing stopped.", Logger::INFO);
    }
}

void PacketSniffer::packetCallback(u_char *user,
                                   const struct pcap_pkthdr *pkthdr,
                                   const u_char *packet) {
    FirewallManager *mgr = reinterpret_cast<FirewallManager *>(user);
    if (pkthdr->len < 34)
        return;
    const u_char *ipHeader = packet + 14;
    int ipHeaderLen = (*ipHeader & 0x0F) * 4;
    if (ipHeaderLen < 20)
        return;
    char srcBuf[INET_ADDRSTRLEN], dstBuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ipHeader + 12, srcBuf, sizeof(srcBuf));
    inet_ntop(AF_INET, ipHeader + 16, dstBuf, sizeof(dstBuf));
    std::string sourceIP = srcBuf;
    std::string destIP = dstBuf;
    u_char protocol = *(ipHeader + 9);
    std::string sourcePort = "0", destPort = "0";

    double payloadEntropy = 0.0;
    double flagAnomaly = 0.0;
    std::string protoStr = "IP";
    std::string dnsQueryDomain = "";
    std::string payloadStr = "";

    if (protocol == IPPROTO_TCP) {
        protoStr = "TCP";
        const u_char *transportHeader = ipHeader + ipHeaderLen;
        sourcePort = std::to_string(ntohs(*(uint16_t *)transportHeader));
        destPort = std::to_string(ntohs(*(uint16_t *)(transportHeader + 2)));

        // Parse TCP flags
        u_char flags = *(transportHeader + 13);
        // Null scan: all flags 0. Xmas scan: FIN, PSH, URG set (0x29) or 0xFF. SYN-FIN scan: both set (0x03)
        if (flags == 0x00 || flags == 0xFF || (flags & 0x29) == 0x29 || (flags & 0x03) == 0x03) {
            flagAnomaly = 1.0;
        }

        // Parse payload
        int tcpHeaderLen = ((*(transportHeader + 12) & 0xF0) >> 4) * 4;
        int ipTotalLen = ntohs(*(uint16_t *)(ipHeader + 2));
        int maxPossiblePayload = pkthdr->len - 14 - ipHeaderLen - tcpHeaderLen;
        int payloadLen = ipTotalLen - ipHeaderLen - tcpHeaderLen;
        if (payloadLen > maxPossiblePayload) {
            payloadLen = maxPossiblePayload;
        }
        if (payloadLen > 0) {
            const u_char *payload = transportHeader + tcpHeaderLen;
            payloadEntropy = calculateEntropy(payload, payloadLen) / 8.0; // Normalize between [0, 1]
            payloadStr = std::string(reinterpret_cast<const char*>(payload), payloadLen);
        }
    } else if (protocol == IPPROTO_UDP) {
        protoStr = "UDP";
        const u_char *transportHeader = ipHeader + ipHeaderLen;
        uint16_t dPortVal = ntohs(*(uint16_t *)(transportHeader + 2));
        sourcePort = std::to_string(ntohs(*(uint16_t *)transportHeader));
        destPort = std::to_string(dPortVal);

        int maxPossiblePayload = pkthdr->len - 14 - ipHeaderLen - 8;
        int payloadLen = ntohs(*(uint16_t *)(transportHeader + 4)) - 8;
        if (payloadLen > maxPossiblePayload) {
            payloadLen = maxPossiblePayload;
        }
        if (payloadLen > 0) {
            const u_char *payload = transportHeader + 8;
            payloadEntropy = calculateEntropy(payload, payloadLen) / 8.0;
            payloadStr = std::string(reinterpret_cast<const char*>(payload), payloadLen);
            if (dPortVal == 53) {
                dnsQueryDomain = parseDNSQuery(payload, payloadLen);
            }
        }
    }

    mgr->processPacket(sourceIP, sourcePort, destIP, destPort, pkthdr->len, protoStr, payloadEntropy, flagAnomaly, dnsQueryDomain, payloadStr);
}
