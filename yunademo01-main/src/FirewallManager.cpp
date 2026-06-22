#include "FirewallManager.h"
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <iomanip>

using namespace std;
using json = nlohmann::json;

// Global pointers for autocompletion
std::mutex globalMutex;
std::atomic<bool> running(true);
std::set<std::string>* blockedIPsPtr = nullptr;
std::map<std::string, BlockedDomain>* blockedDomainsPtr = nullptr;

// CLI Help helper function
std::string getHelpInformation(const std::string &category) {
    if (category.empty()) {
        string help = "YUNA Firewall CLI Help Menu\n\n";
        help += "Available categories (use 'help <category>' to view commands):\n\n";
        help += "block - Commands for blocking and unblocking IPs/websites\n";
        help += "firewall - Commands for managing firewall rules\n";
        help += "network - Commands for network status and maintenance\n";
        help += "threat - Commands for threat detection and response\n";
        help += "vpn - Commands for VPN connections\n";
        help += "logging - Commands for logging and notifications\n";
        help += "status - Commands for system status and exports\n\n";
        help += "exit - Quit the CLI\n";
        return help;
    }
    string help = "YUNA Firewall CLI Commands - " + category + "\n\n";
    if (category == "block") {
        help += "block-ip <ip> - Block an IP address\n\n";
        help += "unblock-ip <ip> - Unblock an IP address\n\n";
        help += "block-website <domain> - Block a website by resolving to IP\n\n";
        help += "block-domain <domain> [category] - Block a domain with optional category\n\n";
        help += "unblock-domain <domain> - Unblock a domain\n\n";
        help += "block-category <category> - Block all domains in a category (e.g., sports)\n\n";
        help += "unblock-category <category> - Unblock all domains in a category\n\n";
        help += "block-all - Block all traffic\n\n";
        help += "unblock-all - Unblock all traffic\n\n";
    } else if (category == "firewall") {
        help += "add-port <port> <protocol> - Add a port rule (e.g., 80 tcp)\n\n";
        help += "remove-port <port> <protocol> - Remove a port rule\n\n";
        help += "add-nat <sourceIP> <destIP> <port> - Add a NAT rule\n\n";
        help += "remove-nat <ruleID> - Remove a NAT rule\n\n";
        help += "optimize - Optimize firewall rules\n\n";
        help += "rollback - Roll back firewall rules\n\n";
        help += "restore-default - Restore default firewall configuration\n\n";
    } else if (category == "network") {
        help += "check-internet - Check internet connectivity\n\n";
        help += "check-health - Check firewall service health\n\n";
        help += "geoip <ip> - Get geographical information for an IP\n\n";
        help += "cleanup-connections - Clean up expired connections\n\n";
    } else if (category == "threat") {
        help += "detect-threat - Check if a threat is detected\n\n";
        help += "respond-threat <ip> - Respond to a threat by blocking an IP\n\n";
        help += "train - Train the neural network with collected data\n\n";
        help += "train-adaptive - Train adaptive model (not implemented for manual input)\n\n";
        help += "auto-heal - Trigger auto-heal process\n\n";
    } else if (category == "vpn") {
        help += "connect-vpn <config_path> - Connect to VPN\n\n";
        help += "disconnect-vpn - Disconnect from VPN\n\n";
    } else if (category == "logging") {
        help += "send-notification <title> <message> - Send a desktop notification\n\n";
        help += "rule-violation <rule> <detail> - Report a rule violation\n\n";
        help += "set-log-level <INFO|WARNING|ERROR|DEBUG> - Set logging level\n\n";
        help += "rotate-logs - Rotate log files\n\n";
        help += "log-message <INFO|WARNING|ERROR|DEBUG> <message> - Log a custom message\n\n";
    } else if (category == "status") {
        help += "status - Show current system status\n\n";
        help += "export-blocked-ips <filename> - Export blocked IPs to a CSV file\n\n";
    } else {
        help = "Unknown category: " + category + "\n\nUse 'help' to see available categories.\n";
    }
    return help;
}

// Static completion functions helper for Readline
static char *completion_generator(const char *text, int state) {
    static int list_index, len;
    static vector<string> matches;
    static string current_cmd;
    if (!state) {
        list_index = 0;
        len = strlen(text);
        matches.clear();
        current_cmd = rl_line_buffer;
        size_t space_pos = current_cmd.find_last_of(" \t");
        if (space_pos != string::npos && space_pos < current_cmd.length() - 1) {
            current_cmd = current_cmd.substr(0, space_pos);
        } else {
            current_cmd.clear();
        }
        if (current_cmd.empty()) {
            static const char *commands[] = {
                "block-ip", "unblock-ip", "panic", "check-internet", "geoip",
                "block-website", "block-domain", "unblock-domain", "block-category",
                "unblock-category", "train", "restore-default", "add-port", "remove-port",
                "connect-vpn", "disconnect-vpn", "status", "export-blocked-ips", "add-nat",
                "remove-nat", "block-all", "unblock-all", "send-notification", "rule-violation",
                "detect-threat", "respond-threat", "train-adaptive", "auto-heal", "rollback",
                "check-health", "optimize", "cleanup-connections", "set-log-level",
                "rotate-logs", "log-message", "help", "exit", nullptr
            };
            for (int i = 0; commands[i]; ++i) {
                if (strncmp(text, commands[i], len) == 0) {
                    matches.push_back(commands[i]);
                }
            }
        } else {
            istringstream iss(current_cmd);
            string cmd;
            iss >> cmd;
            if (cmd == "block-ip" || cmd == "unblock-ip" || cmd == "geoip" || cmd == "respond-threat") {
                lock_guard<mutex> lock(globalMutex);
                if (blockedIPsPtr) {
                    for (const auto &ip : *blockedIPsPtr) {
                        if (strncmp(text, ip.c_str(), len) == 0) {
                            matches.push_back(ip);
                        }
                    }
                }
            } else if (cmd == "block-domain" || cmd == "unblock-domain") {
                {
                    lock_guard<mutex> lock(globalMutex);
                    if (blockedDomainsPtr) {
                        for (const auto &pair : *blockedDomainsPtr) {
                            if (strncmp(text, pair.first.c_str(), len) == 0) {
                                matches.push_back(pair.first);
                            }
                        }
                    }
                }
                static const char *sample_domains[] = {
                    "espn.com", "nfl.com", "nba.com", "cbssports.com", nullptr
                };
                for (int i = 0; sample_domains[i]; ++i) {
                    if (strncmp(text, sample_domains[i], len) == 0) {
                        matches.push_back(sample_domains[i]);
                    }
                }
            } else if (cmd == "block-category" || cmd == "unblock-category") {
                static const char *categories[] = {"sports", "news", "technology", "entertainment",
                                                 "finance", "health", "travel", "education",
                                                 "lifestyle", "science", "gaming", "food", "fashion", nullptr};
                for (int i = 0; categories[i]; ++i) {
                    if (strncmp(text, categories[i], len) == 0) {
                        matches.push_back(categories[i]);
                    }
                }
            } else if (cmd == "add-port" || cmd == "remove-port") {
                static const char *protocols[] = {"tcp", "udp", nullptr};
                for (int i = 0; protocols[i]; ++i) {
                    if (strncmp(text, protocols[i], len) == 0) {
                        matches.push_back(protocols[i]);
                    }
                }
            } else if (cmd == "set-log-level") {
                static const char *levels[] = {"INFO", "WARNING", "ERROR", "DEBUG", nullptr};
                for (int i = 0; levels[i]; ++i) {
                    if (strncmp(text, levels[i], len) == 0) {
                        matches.push_back(levels[i]);
                    }
                }
            } else if (cmd == "help") {
                static const char *categories[] = {"block", "firewall", "network", "threat", "vpn", "logging", "status", nullptr};
                for (int i = 0; categories[i]; ++i) {
                    if (strncmp(text, categories[i], len) == 0) {
                        matches.push_back(categories[i]);
                    }
                }
            }
        }
    }
    if (static_cast<size_t>(list_index) < matches.size()) {
        return strdup(matches[list_index++].c_str());
    }
    return nullptr;
}

static char **firewall_completion(const char *text, int start, int end) {
    (void)start;
    (void)end;
    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, completion_generator);
}

// Convert features helper
std::vector<double> convertToVector(const NetworkFeatures &features) {
    return {features.packetRate, features.packetSize,
            features.connectionDuration, features.portNumber,
            features.payloadEntropy, features.flagAnomaly};
}

// FirewallManager implementations
FirewallManager::FirewallManager(const string &interface)
    : sniffer(interface, this), threatIntel(THREAT_INTEL_API) {
    interfaceName = interface;
    initializeNeuralNetwork();
    curl = curl_easy_init();
    if (!curl) Logger::log("CURL initialization failed.", Logger::ERROR);
    loadBlockedIPs();
    loadBlockedDomains();
    loadConfig();
    blockedIPsPtr = &blockedIPs;
    blockedDomainsPtr = &blockedDomains;
    
    vpnPool = std::make_unique<VPNPoolManager>();
    vpnPool->startHealthMonitor(15);
    
    threatSync = std::make_unique<ThreatIntelSynchronizer>();
    threatSync->startAutoSync(24);

    qosManager = std::make_unique<QosManager>(interface);

    deviceMapper = std::make_unique<DeviceMapper>(interface);
    deviceMapper->startAutoScan(30);

    honeypotManager = std::make_unique<HoneypotManager>();
    ipsEngine = std::make_unique<IpsEngine>();
    dpiClassifier = std::make_unique<DpiClassifier>();
    captivePortal = std::make_unique<CaptivePortal>(this);
    if (captivePortalEnabled) {
        captivePortal->startPortalServer(8082);
    }
    honeypotManager->setTriggerCallback([this](const std::string& violatorIP, int port) {
        respondToThreat(violatorIP);
        sendNotification("Honeypot Triggered", "Blocked scanning host: " + violatorIP + " on trap port " + to_string(port));
    });
    honeypotManager->startHoneypot();

    if (!sniffer.start()) {
        Logger::log("Failed to start packet sniffer.", Logger::ERROR);
    }
    threatMonitorThread = thread(&FirewallManager::threatMonitor, this);
    maintenanceThread = thread(&FirewallManager::systemMaintenance, this);
}

FirewallManager::~FirewallManager() {
    running = false;
    cv.notify_all();
    if (vpnPool) vpnPool->stopHealthMonitor();
    if (threatSync) threatSync->stopAutoSync();
    if (deviceMapper) deviceMapper->stopAutoScan();
    if (honeypotManager) honeypotManager->stopHoneypot();
    sniffer.stop();
    if (threatMonitorThread.joinable())
        threatMonitorThread.join();
    if (maintenanceThread.joinable())
        maintenanceThread.join();
    if (curl)
        curl_easy_cleanup(curl);
    saveConfig();
    saveBlockedIPs();
    saveBlockedDomains();
    neuralNetwork->saveModel(MODEL_FILE);
}

string FirewallManager::executeSystemCommand(const string &cmd) {
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        Logger::log("Failed to execute command: " + cmd, Logger::ERROR);
        return "";
    }
    char buffer[128];
    string result;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    int exitCode = pclose(pipe);
    if (exitCode != 0) {
        Logger::log("Command " + cmd + " exited with code " + to_string(exitCode),
                    Logger::WARNING);
    }
    return result;
}

void FirewallManager::initializeNeuralNetwork() {
    neuralNetwork = make_unique<NeuralNetwork>(6, 12, 6, 1);
    if (ifstream(MODEL_FILE).good()) {
        neuralNetwork->loadModel(MODEL_FILE);
        if (neuralNetwork->getInputSize() != 6) {
            Logger::log("Model input size mismatch. Reinitializing new neural network with 6 features.", Logger::WARNING);
            neuralNetwork = make_unique<NeuralNetwork>(6, 12, 6, 1);
        }
    } else {
        Logger::log("No model file found, initializing new neural network.",
                    Logger::INFO);
    }
}

void FirewallManager::loadBlockedIPs() {
    ifstream file(BLOCKED_IPS_FILE);
    if (file.is_open()) {
        json j;
        file >> j;
        for (const auto &ip : j["blocked_ips"]) {
            blockedIPs.insert(ip);
        }
        file.close();
        Logger::log("Loaded " + to_string(blockedIPs.size()) + " blocked IPs.",
                    Logger::INFO);
    }
}

void FirewallManager::saveBlockedIPs() {
    json j;
    j["blocked_ips"] = vector<string>(blockedIPs.begin(), blockedIPs.end());
    ofstream file(BLOCKED_IPS_FILE);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
        Logger::log("Saved blocked IPs to file.", Logger::INFO);
    } else {
        Logger::log("Failed to save blocked IPs.", Logger::ERROR);
    }
}

void FirewallManager::loadBlockedDomains() {
    ifstream file(BLOCKED_DOMAINS_FILE);
    if (!file.is_open()) {
        Logger::log("No blocked domains file found.", Logger::INFO);
        return;
    }
    json j;
    try {
        file >> j;
        for (const auto &domain : j["blocked_domains"]) {
            BlockedDomain bd;
            bd.domain = domain["domain"];
            bd.category = domain["category"];
            for (const auto &ip : domain["resolvedIPs"]) {
                bd.resolvedIPs.insert(ip.get<string>());
                blockedIPs.insert(ip.get<string>());
            }
            blockedDomains[bd.domain] = bd;
        }
        file.close();
        Logger::log("Loaded " + to_string(blockedDomains.size()) +
                    " blocked domains.",
                    Logger::INFO);
    } catch (const exception &e) {
        Logger::log("Error loading blocked domains: " + string(e.what()),
                    Logger::ERROR);
    }
}

void FirewallManager::saveBlockedDomains() {
    json j;
    vector<json> domains;
    for (const auto &pair : blockedDomains) {
        json domain;
        domain["domain"] = pair.first;
        domain["category"] = pair.second.category;
        domain["resolvedIPs"] = vector<string>(pair.second.resolvedIPs.begin(),
                                             pair.second.resolvedIPs.end());
        domains.push_back(domain);
    }
    j["blocked_domains"] = domains;
    ofstream file(BLOCKED_DOMAINS_FILE);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
        Logger::log("Saved blocked domains to file.", Logger::INFO);
    } else {
        Logger::log("Failed to save blocked domains.", Logger::ERROR);
    }
}

string FirewallManager::getDomainCategory(const string &domain) {
    if (!curl) {
        Logger::log("CURL not initialized for category lookup.", Logger::ERROR);
        return "unknown";
    }
    string url = "https://api.webshrinker.com/categories/v3/" + domain;
    string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(
        curl, CURLOPT_WRITEFUNCTION,
        [](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
            ((string *)userdata)->append(ptr, size * nmemb);
            return size * nmemb;
        });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Authorization: Bearer YOUR_API_KEY");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (res == CURLE_OK) {
        try {
            json j = json::parse(response);
            if (j.contains("categories") && !j["categories"].empty()) {
                return j["categories"][0].get<string>();
            }
        } catch (const exception &e) {
            Logger::log("Category parse error for " + domain + ": " + e.what(),
                        Logger::ERROR);
        }
    } else {
        Logger::log("Category request failed for " + domain + ": " +
                    curl_easy_strerror(res),
                    Logger::ERROR);
    }
    return "unknown";
}

void FirewallManager::blockDomain(const string &domain, const string &category) {
    if (!isValidDomain(domain)) {
        Logger::log("Invalid domain requested for blocking: " + domain, Logger::ERROR);
        cout << "Error: Invalid domain." << endl;
        return;
    }
    string sanitizedCategory = sanitizeShellArg(category);
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int status = getaddrinfo(domain.c_str(), nullptr, &hints, &res);
    if (status != 0) {
        Logger::log("Failed to resolve " + domain + ": " + gai_strerror(status),
                    Logger::ERROR);
        cout << "Failed to resolve " + domain + ": " + gai_strerror(status)
             << endl;
        return;
    }
    string resolvedCategory = sanitizedCategory.empty() ? getDomainCategory(domain) : sanitizedCategory;
    resolvedCategory = sanitizeShellArg(resolvedCategory);
    BlockedDomain blockedDomain;
    blockedDomain.domain = domain;
    blockedDomain.category = resolvedCategory;
    char ipStr[INET_ADDRSTRLEN];
    for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
        void *addr = &((struct sockaddr_in *)p->ai_addr)->sin_addr;
        inet_ntop(p->ai_family, addr, ipStr, sizeof(ipStr));
        string ip = ipStr;
        if (isValidIP(ip)) {
            string cmd = "firewall-cmd --permanent --add-rich-rule='rule "
                         "family=\"ipv4\" source address=\"" +
                         ip + "\" drop'";
            executeSystemCommand(cmd);
            {
                lock_guard<mutex> lock(globalMutex);
                blockedIPs.insert(ip);
            }
            blockedDomain.resolvedIPs.insert(ip);
            Logger::log("Blocked IP " + ip + " for domain " + domain,
                        Logger::WARNING);
        }
    }
    freeaddrinfo(res);
    executeSystemCommand("firewall-cmd --reload");
    lock_guard<mutex> lock(globalMutex);
    blockedDomains[domain] = blockedDomain;
    saveBlockedDomains();
    Logger::log("Blocked domain " + domain +
                " (category: " + blockedDomain.category + ")",
                Logger::INFO);
    cout << "Blocked domain " + domain +
            " (category: " + blockedDomain.category + ")"
         << endl;
}

void FirewallManager::unblockDomain(const string &domain) {
    if (!isValidDomain(domain)) {
        Logger::log("Invalid domain requested for unblocking: " + domain, Logger::ERROR);
        cout << "Error: Invalid domain." << endl;
        return;
    }
    lock_guard<mutex> lock(globalMutex);
    auto it = blockedDomains.find(domain);
    if (it == blockedDomains.end()) {
        Logger::log("Domain " + domain + " not blocked.", Logger::INFO);
        cout << "Domain " + domain + " not blocked." << endl;
        return;
    }
    for (const auto &ip : it->second.resolvedIPs) {
        if (isValidIP(ip)) {
            string cmd = "firewall-cmd --permanent --remove-rich-rule='rule "
                         "family=\"ipv4\" source address=\"" +
                         ip + "\" drop'";
            executeSystemCommand(cmd);
            blockedIPs.erase(ip);
            Logger::log("Unblocked IP " + ip + " for domain " + domain,
                        Logger::INFO);
        }
    }
    executeSystemCommand("firewall-cmd --reload");
    blockedDomains.erase(it);
    saveBlockedDomains();
    Logger::log("Unblocked domain " + domain, Logger::INFO);
    cout << "Unblocked domain " + domain << endl;
}

void FirewallManager::blockCategory(const string &category) {
    vector<string> domains;
    if (category == "sports") {
        domains = {"espn.com", "nfl.com", "nba.com", "cbssports.com", "mlb.com",
                   "nhl.com", "foxsports.com", "si.com", "bleacherreport.com",
                   "sportingnews.com", "nbcsports.com", "theathletic.com",
                   "sbnation.com", "goal.com", "skysports.com", "eurosport.com",
                   "sportbible.com", "deadspin.com", "yardbarker.com", "thescore.com",
                   "espncricinfo.com", "cricket.com.au", "fifa.com", "uefa.com",
                   "olympics.com", "golf.com", "pgatour.com", "tennis.com",
                   "atptour.com", "wtatennis.com", "runnersworld.com", "bicycling.com",
                   "swimmingworldmagazine.com", "espnfc.com", "mlssoccer.com",
                   "nascar.com", "formula1.com", "motorsport.com", "cyclingnews.com",
                   "boxingscene.com", "mmafighting.com", "sherdog.com", "rugbypass.com",
                   "worldrugby.org", "hockeynews.com", "lacrossetribune.com",
                   "trackandfieldnews.com", "track360.com", "talksport.com",
                   "givemesport.com", "sportstar.thehindu.com", "90min.com"};
    } else if (category == "news") {
        domains = {"cnn.com", "bbc.com", "nytimes.com", "reuters.com",
                   "theguardian.com", "apnews.com", "npr.org", "aljazeera.com",
                   "wsj.com", "washingtonpost.com", "bloomberg.com", "ft.com",
                   "abcnews.go.com", "cbsnews.com", "nbcnews.com", "usatoday.com",
                   "foxnews.com", "newsweek.com", "time.com", "huffpost.com",
                   "politico.com", "axios.com", "vox.com", "slate.com",
                   "thehill.com", "nypost.com", "dailymail.co.uk", "telegraph.co.uk",
                   "independent.co.uk", "mirror.co.uk", "express.co.uk", "skynews.com",
                   "cnbc.com", "forbes.com", "businessinsider.com", "news.com.au",
                   "smh.com.au", "theage.com.au", "japantimes.co.jp", "france24.com",
                   "dw.com", "rt.com", "spiegel.de", "lemonde.fr", "elpais.com",
                   "timesofindia.indiatimes.com", "hindustantimes.com", "straitstimes.com",
                   "scmp.com", "nationalpost.com", "globeandmail.com"};
    } else if (category == "technology") {
        domains = {"techcrunch.com", "wired.com", "theverge.com", "arstechnica.com",
                   "cnet.com", "engadget.com", "gizmodo.com", "zdnet.com",
                   "techradar.com", "mashable.com", "venturebeat.com", "digitaltrends.com",
                   "thenextweb.com", "geekwire.com", "bgr.com", "slashgear.com",
                   "tomshardware.com", "anandtech.com", "pcmag.com", "computerworld.com",
                   "itworld.com", "infoworld.com", "networkworld.com", "techrepublic.com",
                   "gadgethacks.com", "makeuseof.com", "howtogeek.com", "lifehacker.com",
                   "androidauthority.com", "9to5mac.com", "9to5google.com",
                   "androidcentral.com", "appleinsider.com", "pocket-lint.com",
                   "trustedreviews.com", "techspot.com", "extremetech.com",
                   "hardwarezone.com", "overclock.net", "linustechtips.com",
                   "arstechnica.co.uk", "techadvisor.com", "windowscentral.com",
                   "macrumors.com", "droid-life.com", "phonearena.com", "gsmarena.com",
                   "xda-developers.com", "ventureburn.com", "siliconangle.com",
                   "betanews.com"};
    } else if (category == "entertainment") {
        domains = {"variety.com",      "hollywoodreporter.com",
                   "ew.com",           "tmz.com",
                   "eonline.com",      "vulture.com",
                   "deadline.com",     "rollingstone.com",
                   "billboard.com",    "mtv.com",
                   "people.com",       "usmagazine.com",
                   "etonline.com",     "accessonline.com",
                   "popsugar.com",     "justjared.com",
                   "screenrant.com",   "collider.com",
                   "indiewire.com",    "slashfilm.com",
                   "cinemablend.com",  "movieweb.com",
                   "comingsoon.net",   "joblo.com",
                   "fandango.com",     "rottentomatoes.com",
                   "metacritic.com",   "imdb.com",
                   "tvguide.com",      "tvline.com",
                   "teenvogue.com",    "vanityfair.com",
                   "gq.com",           "vogue.com",
                   "elle.com",         "harpersbazaar.com",
                   "cosmopolitan.com", "glamour.com",
                   "instyle.com",      "esquire.com",
                   "nme.com",          "pitchfork.com",
                   "stereogum.com",    "consequence.net",
                   "avclub.com",       "denofgeek.com",
                   "screendaily.com",  "thewrap.com",
                   "bustle.com",       "refinery29.com",
                   "complex.com"};
    } else if (category == "finance") {
        domains = {"bloomberg.com", "cnbc.com", "marketwatch.com", "forbes.com",
                   "businessinsider.com", "ft.com", "wsj.com", "investopedia.com",
                   "fool.com", "barrons.com", "kiplinger.com", "money.cnn.com",
                   "thestreet.com", "morningstar.com", "seekingalpha.com",
                   "zacks.com", "benzinga.com", "nasdaq.com", "nyse.com",
                   "investorplace.com", "financialpost.com", "economist.com",
                   "moneycontrol.com", "livemint.com", "etf.com", "bankrate.com",
                   "nerdwallet.com", "creditkarma.com", "smartasset.com",
                   "thebalance.com", "valuepenguin.com", "moneycrashers.com",
                   "business-standard.com", "economictimes.indiatimes.com",
                   "finance.yahoo.com", "cnbctv18.com", "marketrealist.com",
                   "themotleyfool.com", "tipranks.com", "barchart.com",
                   "tradingview.com", "investing.com", "finviz.com", "stockcharts.com",
                   "bloombergquint.com", "moneyweek.com", "financialexpress.com",
                   "ibtimes.com", "dailyfx.com", "fxstreet.com", "forexlive.com"};
    } else if (category == "health") {
        domains = {"webmd.com", "mayoclinic.org", "healthline.com", "medscape.com",
                   "nih.gov", "cdc.gov", "who.int", "medicalnewstoday.com",
                   "everydayhealth.com", "health.com", "menshealth.com",
                   "womenshealthmag.com", "prevention.com", "verywellhealth.com",
                   "psychologytoday.com", "healthgrades.com", "drugs.com",
                   "rxlist.com", "merckmanuals.com", "medlineplus.gov",
                   "livestrong.com", "self.com", "shape.com", "eatingwell.com",
                   "myfitnesspal.com", "fitbit.com", "mensjournal.com",
                   "runnersworld.com", "yogajournal.com", "mindbodygreen.com",
                   "health.harvard.edu", "clevelandclinic.org", "hopkinsmedicine.org",
                   "diabetes.org", "heart.org", "cancer.org", "arthritis.org",
                   "psychcentral.com", "verywellmind.com", "verywellfit.com",
                   "nutrition.org", "eatright.org", "foodnetwork.com",
                   "cookinglight.com", "bonappetit.com", "epicurious.com",
                   "seriouseats.com", "healthcentral.com", "spine-health.com",
                   "sleepfoundation.org", "drweil.com"};
    } else if (category == "travel") {
        domains = {"tripadvisor.com", "lonelyplanet.com", "expedia.com",
                   "booking.com", "kayak.com", "travelandleisure.com",
                   "cntraveler.com", "fodors.com", "frommers.com", "roughguides.com",
                   "skyscanner.com", "orbitz.com", "travelocity.com", "hotels.com",
                   "agoda.com", "trivago.com", "viator.com", "airbnb.com",
                   "vrbo.com", "homeaway.com", "nationalgeographic.com",
                   "atlasobscura.com", "thepointsguy.com", "travelzoo.com",
                   "ricksteves.com", "budgettravel.com", "afar.com",
                   "matadornetwork.com", "nomadicmatt.com", "travelpulse.com",
                   "smartertravel.com", "oyster.com", "jetsetter.com",
                   "luxurytraveladvisor.com", "condenasttraveller.com",
                   "travelweekly.com", "wanderlust.co.uk", "cntraveller.in",
                   "backpacker.com", "outsideonline.com", "adventure.com",
                   "tourradar.com", "intrepidtravel.com", "gadventures.com",
                   "cruisecritic.com", "cruise.com", "vacationstogo.com",
                   "cruiseline.com", "travelchannel.com", "flightaware.com",
                   "seatguru.com"};
    } else if (category == "education") {
        domains = {"coursera.org", "edx.org", "khanacademy.org", "udemy.com",
                   "futurelearn.com", "pluralsight.com", "skillshare.com",
                   "lynda.com", "codecademy.com", "udacity.com", "brilliant.org",
                   "masterclass.com", "study.com", "chegg.com", "quizlet.com",
                   "duolingo.com", "memrise.com", "brainly.com", "sparknotes.com",
                   "cliffnotes.com", "openculture.com", "ted.com", "mit.edu",
                   "stanford.edu", "harvard.edu", "yale.edu", "ox.ac.uk",
                   "cam.ac.uk", "open.edu", "academic.oup.com", "jstor.org",
                   "scholar.google.com", "researchgate.net", "academia.edu",
                   "springer.com", "elsevier.com", "wiley.com", "tandfonline.com",
                   "sagepub.com", "eric.ed.gov", "nces.ed.gov", "education.com",
                   "scholastic.com", "pbslearningmedia.org", "nationalgeographic.org",
                   "britannica.com", "merriam-webster.com", "dictionary.com",
                   "thesaurus.com", "grammarly.com"};
    } else if (category == "lifestyle") {
        domains = {"popsugar.com", "refinery29.com", "bustle.com", "elle.com",
                   "vogue.com", "gq.com", "esquire.com", "harpersbazaar.com",
                   "cosmopolitan.com", "glamour.com", "instyle.com", "teenvogue.com",
                   "marthastewart.com", "realsimple.com", "betterhomesandgardens.com",
                   "hgtv.com", "housebeautiful.com", "architecturaldigest.com",
                   "dwell.com", "apartmenttherapy.com", "elledecor.com",
                   "veranda.com", "goodhousekeeping.com", "countryliving.com",
                   "southernliving.com", "myrecipes.com", "epicurious.com",
                   "bonappetit.com", "seriouseats.com", "foodandwine.com",
                   "delish.com", "thekitchn.com", "allrecipes.com", "foodnetwork.com",
                   "cookinglight.com", "tasteofhome.com", "purewow.com", "goop.com",
                   "mindbodygreen.com", "wellandgood.com", "thecut.com",
                   "manrepeller.com", "whowhatwear.com", "fashionista.com",
                   "racked.com", "stylecaster.com", "byrdie.com",
                   "cupcakesandcashmere.com", "lovelyish.com", "theeverygirl.com",
                   "galmeetsglam.com"};
    } else if (category == "science") {
        domains = {"sciencemag.org", "nature.com", "sciencedaily.com",
                   "scientificamerican.com", "newscientist.com", "livescience.com",
                   "space.com", "astronomy.com", "discovermagazine.com", "popsci.com",
                   "nationalgeographic.com", "smithsonianmag.com", "sciencenews.org",
                   "phys.org", "arstechnica.com", "wired.com", "the-scientist.com",
                   "eurekalert.org", "sciencedirect.com", "plos.org",
                   "frontiersin.org", "springer.com", "elsevier.com",
                   "researchgate.net", "pubmed.ncbi.nlm.nih.gov", "scholar.google.com",
                   "nasa.gov", "esa.int", "cern.ch", "quantum.gov", "energy.gov",
                   "noaa.gov", "usgs.gov", "nih.gov", "nsf.gov",
                   "sciencenewsforstudents.org", "askascientist.com",
                   "sciencefocus.com", "cosmosmagazine.com", "sciencealert.com",
                   "futurism.com", "quantamagazine.org", "newatlas.com",
                   "sciencetimes.com", "theconversation.com", "nautil.us",
                   "sciencefriday.com", "skyandtelescope.com", "earthsky.org",
                   "universetoday.com", "physicsworld.com"};
    } else if (category == "gaming") {
        domains = {"ign.com", "gamespot.com", "polygon.com", "kotaku.com",
                   "eurogamer.net", "pcgamer.com", "rockpapershotgun.com",
                   "gamesradar.com", "gameinformer.com", "destructoid.com",
                   "joystiq.com", "shacknews.com", "vg247.com", "escapistmagazine.com",
                   "gamezebo.com", "toucharcade.com", "pocketgamer.com",
                   "nintendolife.com", "pushsquare.com", "purexbox.com",
                   "gamesindustry.biz", "gamasutra.com", "venturebeat.com",
                   "mmorpg.com", "rpgsite.net", "dualshockers.com", "wccftech.com",
                   "thegamer.com", "gamepur.com", "gamingbolt.com", "techraptor.net",
                   "hardcoregamer.com", "gamecrate.com", "playstationlifestyle.net",
                   "xboxachievements.com", "trueachievements.com", "truegaming.net",
                   "gameskinny.com", "gameranx.com", "gamerevolution.com", "n4g.com",
                   "gamespark.com", "gamefront.com", "gamersheroes.com", "gamerant.com",
                   "gamespew.com", "indiegamewebsite.com", "indiegamesplus.com",
                   "freegames.com", "epicgames.com", "steamcommunity.com"};
    } else if (category == "food") {
        domains = {"foodnetwork.com", "bonappetit.com", "epicurious.com",
                   "seriouseats.com", "allrecipes.com", "thekitchn.com",
                   "delish.com", "tasteofhome.com", "foodandwine.com",
                   "cookinglight.com", "myrecipes.com", "eatingwell.com",
                   "saveur.com", "food52.com", "smittenkitchen.com", "seriouseats.com",
                   "yummly.com", "bbcgoodfood.com", "jamieoliver.com", "nigella.com",
                   "marthastewart.com", "pioneerwoman.com", "halfbakedharvest.com",
                   "pinchofyum.com", "budgetbytes.com", "minimalistbaker.com",
                   "sallysbakingaddiction.com", "joyofbaking.com",
                   "kingarthurbaking.com", "tasty.co", "deliaonline.com",
                   "greatbritishchefs.com", "gourmettraveller.com.au",
                   "taste.com.au", "foodrepublic.com", "eater.com",
                   "thespruceeats.com", "simplyrecipes.com", "cookieandkate.com",
                   "loveandlemons.com", "101cookbooks.com", "ohsheglows.com",
                   "downshiftology.com", "themediterraneandish.com", "skinnytaste.com",
                   "gimmesomeoven.com", "averiecooks.com", "cafedelites.com",
                   "damn-delicious.com", "bakingmischief.com", "justonecookbook.com",
                   "recipetineats.com"};
    } else if (category == "fashion") {
        domains = {"vogue.com", "elle.com", "harpersbazaar.com", "gq.com",
                   "esquire.com", "instyle.com", "cosmopolitan.com", "glamour.com",
                   "teenvogue.com", "whowhatwear.com", "fashionista.com",
                   "thecut.com", "manrepeller.com", "stylecaster.com", "byrdie.com",
                   "refinery29.com", "popsugar.com", "bustle.com", "racked.com",
                   "coveteur.com", "elleuk.com", "vogue.co.uk", "harpersbazaar.com.au",
                   "vogue.in", "gqindia.in", "ellecanada.com", "fashionmagazine.com",
                   "vogue.fr", "elle.fr", "gqmagazine.fr", "vogue.it", "elle.it",
                   "vogue.es", "elle.es", "gq.com.au", "vogue.com.au",
                   "whowhatwear.co.uk", "net-a-porter.com", "farfetch.com",
                   "ssense.com", "matchesfashion.com", "mytheresa.com",
                   "modaoperandi.com", "shopstyle.com", "revolve.com", "zara.com",
                   "hm.com", "uniqlo.com", "nordstrom.com", "saksfifthavenue.com",
                   "bloomingdales.com"};
    } else {
        Logger::log("Category " + category + " not supported.", Logger::WARNING);
        cout << "Category " + category + " not supported." << endl;
    }
    for (const auto &domain : domains) {
        blockDomain(domain, category);
    }
    Logger::log("Blocked all domains in category: " + category, Logger::INFO);
    cout << "Blocked all domains in category: " + category << endl;
}

void FirewallManager::unblockCategory(const string &category) {
    vector<string> domainsToUnblock;
    {
        lock_guard<mutex> lock(globalMutex);
        for (const auto &pair : blockedDomains) {
            if (pair.second.category == category) {
                domainsToUnblock.push_back(pair.first);
            }
        }
    }
    for (const auto &domain : domainsToUnblock) {
        unblockDomain(domain);
    }
    Logger::log("Unblocked all domains in category: " + category, Logger::INFO);
    cout << "Unblocked all domains in category: " + category << endl;
}

void FirewallManager::exportBlockedIPsToCSV(const string &filename) {
    ofstream file(filename);
    if (!file.is_open()) {
        Logger::log("Failed to open file for exporting blocked IPs: " + filename,
                    Logger::ERROR);
        return;
    }
    file << "Blocked IPs\n";
    for (const auto &ip : blockedIPs) {
        file << ip << "\n";
    }
    file.close();
    Logger::log("Blocked IPs exported to " + filename, Logger::INFO);
}

NetworkFeatures FirewallManager::extractFeatures(const ConnectionState &connection) {
    NetworkFeatures features;
    try {
        double port = stod(connection.destPort);
        features.portNumber = port / 65535.0;
    } catch (const exception &e) {
        features.portNumber = 0.0;
        Logger::log("Invalid port number: " + connection.destPort,
                    Logger::WARNING);
    }
    auto now = chrono::system_clock::now();
    double timeDiff =
        chrono::duration<double>(now - connection.lastUpdate).count();
    features.packetRate =
        (timeDiff > 0.0)
            ? static_cast<double>(connection.packetCount) / timeDiff
            : 0.0;
    features.packetSize =
        static_cast<double>(connection.totalBytes) / (1024.0 * 1024.0);
    features.connectionDuration = timeDiff / 3600.0;
    features.payloadEntropy = (connection.packetCount > 0) ? (connection.accumulatedEntropy / connection.packetCount) : 0.0;
    features.flagAnomaly = (connection.packetCount > 0) ? (connection.accumulatedAnomalies / connection.packetCount) : 0.0;
    return features;
}

void FirewallManager::addNatRule(const string &sourceIP, const string &destIP,
                                 const string &port) {
    if (!isValidIP(sourceIP) || !isValidIP(destIP) || !isValidPort(port)) {
        Logger::log("Invalid parameters for NAT rule. Src: " + sourceIP + ", Dest: " + destIP + ", Port: " + port, Logger::ERROR);
        cout << "Error: Invalid IP or port parameters for NAT rule." << endl;
        return;
    }
    string cmd = "firewall-cmd --permanent --add-rich-rule='rule "
                 "family=\"ipv4\" source address=\"" +
                 sourceIP + "\" destination address=\"" + destIP +
                 "\" port port=\"" + port + "\" protocol=\"tcp\" accept'";
    executeSystemCommand(cmd);
    executeSystemCommand("firewall-cmd --reload");
    Logger::log("Added NAT rule: " + sourceIP + " -> " + destIP + ":" + port,
                Logger::INFO);
}

void FirewallManager::removeNatRule(const string &ruleID) {
    string sanitizedRuleID = sanitizeShellArg(ruleID);
    string cmd = "firewall-cmd --permanent --remove-rich-rule='" + sanitizedRuleID + "'";
    executeSystemCommand(cmd);
    executeSystemCommand("firewall-cmd --reload");
    Logger::log("Removed NAT rule: " + sanitizedRuleID, Logger::INFO);
}

void FirewallManager::checkInternetConnectivity() {
    string cmd = "ping -c 1 -W 2 google.com > /dev/null 2>&1";
    int status = system(cmd.c_str());
    internetStatus = (status == 0);
    if (internetStatus) {
        Logger::log("Internet is available.", Logger::INFO);
        cout << "Internet is available." << endl;
    } else {
        Logger::log("Internet is not available.", Logger::INFO);
        cout << "Internet is not available." << endl;
    }
}

void FirewallManager::connectToVpn(const string &configPath) {
    if (configPath.empty()) {
        Logger::log("VPN configuration name or path is empty.", Logger::ERROR);
        cout << "Error: Empty VPN profile or path." << endl;
        return;
    }
    
    // Check if it is a local file configuration
    if (access(configPath.c_str(), F_OK) == 0) {
        std::string type = "openvpn";
        if (configPath.find(".conf") != std::string::npos) {
            type = "wireguard";
        }
        std::string name = configPath;
        size_t lastSlash = name.find_last_of("/\\");
        if (lastSlash != std::string::npos) {
            name = name.substr(lastSlash + 1);
        }
        size_t dot = name.find_last_of('.');
        if (dot != std::string::npos) {
            name = name.substr(0, dot);
        }
        
        vpnPool->addProfile(name, type, configPath);
        vpnPool->connectProfile(name);
    } else {
        // Otherwise treat configPath as the profile name directly
        vpnPool->connectProfile(configPath);
    }
}

void FirewallManager::disconnectVpn() {
    vpnPool->disconnectActive();
    Logger::log("VPN disconnected.", Logger::INFO);
    cout << "VPN disconnected." << endl;
}

bool FirewallManager::isVpnConnected() {
    return vpnPool->isVPNConnected();
}

void FirewallManager::blockAllTraffic() {
    executeSystemCommand("firewall-cmd --panic-on");
    panicModeEnabled = true;
    Logger::log("All traffic blocked.", Logger::WARNING);
    cout << "All traffic blocked." << endl;
}

void FirewallManager::unblockAllTraffic() {
    executeSystemCommand("firewall-cmd --panic-off");
    panicModeEnabled = false;
    Logger::log("All traffic unblocked.", Logger::INFO);
    cout << "All traffic unblocked." << endl;
}

bool FirewallManager::isValidIP(const string &ip) {
    if (ip.empty()) return false;
    size_t slashPos = ip.find('/');
    if (slashPos != string::npos) {
        string ipPart = ip.substr(0, slashPos);
        string maskPart = ip.substr(slashPos + 1);
        struct sockaddr_in sa;
        struct sockaddr_in6 sa6;
        bool ipValid = (inet_pton(AF_INET, ipPart.c_str(), &(sa.sin_addr)) == 1);
        bool ip6Valid = (inet_pton(AF_INET6, ipPart.c_str(), &(sa6.sin6_addr)) == 1);
        if (!ipValid && !ip6Valid) return false;
        try {
            int mask = stoi(maskPart);
            if (ipValid) {
                return mask >= 0 && mask <= 32;
            } else {
                return mask >= 0 && mask <= 128;
            }
        } catch (...) {
            return false;
        }
    }
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    return (inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) == 1) ||
           (inet_pton(AF_INET6, ip.c_str(), &(sa6.sin6_addr)) == 1);
}

bool FirewallManager::isValidDomain(const string &domain) {
    if (domain.empty() || domain.length() > 253) return false;
    regex domainRegex("^([a-zA-Z0-9-]{1,63}\\.)+[a-zA-Z]{2,63}$");
    return regex_match(domain, domainRegex);
}

bool FirewallManager::isValidPort(const string &port) {
    if (port.empty()) return false;
    try {
        size_t idx;
        int p = stoi(port, &idx);
        return idx == port.length() && p >= 1 && p <= 65535;
    } catch (...) {
        return false;
    }
}

string FirewallManager::sanitizeShellArg(const string &arg) {
    string sanitized;
    for (char c : arg) {
        if (isalnum(c) || c == ' ' || c == '.' || c == '-' || c == ':' || c == '_' || c == '/') {
            sanitized += c;
        } else {
            sanitized += '_';
        }
    }
    return sanitized;
}

void FirewallManager::blockIPAddress(const string &ipAddress) {
    if (!isValidIP(ipAddress)) {
        Logger::log("Invalid IP address requested for blocking: " + ipAddress, Logger::ERROR);
        cout << "Error: Invalid IP address." << endl;
        return;
    }
    {
        lock_guard<mutex> lock(globalMutex);
        if (blockedIPs.count(ipAddress) > 0) {
            Logger::log("IP " + ipAddress + " already blocked.", Logger::INFO);
            cout << "IP " + ipAddress + " already blocked." << endl;
            return;
        }
    }
    
    string cmd = "firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"" +
                 ipAddress + "\" drop'";
    executeSystemCommand(cmd);
    executeSystemCommand("firewall-cmd --reload");
    {
        lock_guard<mutex> lock(globalMutex);
        blockedIPs.insert(ipAddress);
    }

    bool isConfirmedThreat = threatIntel.isThreatIP(ipAddress);
    if (isConfirmedThreat) {
        Logger::log("Blocked IP " + ipAddress + " (threat intel confirmed).", Logger::WARNING);
        cout << "Blocked IP " + ipAddress + " (threat intel confirmed)." << endl;
    } else {
        Logger::log("Blocked IP " + ipAddress + " (manual/auto response override).", Logger::WARNING);
        cout << "Blocked IP " + ipAddress + "." << endl;
    }
}

void FirewallManager::unblockIPAddress(const string &ipAddress) {
    if (!isValidIP(ipAddress)) {
        Logger::log("Invalid IP address requested for unblocking: " + ipAddress, Logger::ERROR);
        cout << "Error: Invalid IP address." << endl;
        return;
    }
    {
        lock_guard<mutex> lock(globalMutex);
        if (blockedIPs.count(ipAddress) == 0) {
            Logger::log("IP " + ipAddress + " not blocked.", Logger::INFO);
            cout << "IP " + ipAddress + " not blocked." << endl;
            return;
        }
    }
    string cmd = "firewall-cmd --permanent --remove-rich-rule='rule family=\"ipv4\" source address=\"" +
                 ipAddress + "\" drop'";
    executeSystemCommand(cmd);
    executeSystemCommand("firewall-cmd --reload");
    {
        lock_guard<mutex> lock(globalMutex);
        blockedIPs.erase(ipAddress);
    }
    Logger::log("Unblocked IP " + ipAddress, Logger::INFO);
    cout << "Unblocked IP " + ipAddress << endl;
}

void FirewallManager::getGeoIP(const string &ip) {
    auto isValidIP = [](const string &ipAddress) -> bool {
        regex ipRegex("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
        return regex_match(ipAddress, ipRegex);
    };

    if (!isValidIP(ip)) {
        string error = "Invalid IP address: " + ip;
        Logger::log(error, Logger::ERROR);
        cout << error << endl;
        return;
    }
    if (!curl) {
        string error = "CURL handle not initialized";
        Logger::log(error, Logger::ERROR);
        cout << error << endl;
        return;
    }
    string url = "http://ip-api.com/json/" + ip;
    string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(
        curl, CURLOPT_WRITEFUNCTION,
        [](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t {
            ((string *)userdata)->append(ptr, size * nmemb);
            return size * nmemb;
        });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        Logger::log("Raw API response: " + response, Logger::INFO);
        try {
            json j = json::parse(response);
            if (j.contains("status") && j["status"] == "fail") {
                string error = "GeoIP API error: " + j["message"].get<string>();
                Logger::log(error, Logger::ERROR);
                cout << error << endl;
                return;
            }
            string country = j.contains("country") ? j["country"].get<string>() : "Unknown";
            string city = j.contains("city") ? j["city"].get<string>() : "Unknown";
            string message = "GeoIP for " + ip + ": Country=" + country + ", City=" + city;
            Logger::log(message, Logger::INFO);
            cout << message << endl;
            if (country == "North Korea" || country == "Iran") {
                blockIPAddress(ip);
            }
        } catch (const exception &e) {
            string error = "GeoIP parse error: " + string(e.what());
            Logger::log(error, Logger::ERROR);
            cout << error << endl;
        }
    } else {
        string error = "GeoIP request failed: " + string(curl_easy_strerror(res));
        Logger::log(error, Logger::ERROR);
        cout << error << endl;
    }
    this_thread::sleep_for(chrono::milliseconds(1500));
}

void FirewallManager::cleanupExpiredConnections() {
    auto now = chrono::system_clock::now();
    vector<vector<double>> tempInputs, tempLabels;
    lock_guard<mutex> lock(globalMutex);
    for (auto it = connectionTable.begin(); it != connectionTable.end();) {
        double timeDiff = chrono::duration<double>(now - it->second.lastUpdate).count();
        if (timeDiff > TIMEOUT_SECONDS) {
            NetworkFeatures f = extractFeatures(it->second);
            vector<double> input = convertToVector(f);
            vector<double> label = {it->second.wasBlocked ? 1.0 : 0.0};
            tempInputs.push_back(input);
            tempLabels.push_back(label);
            it = connectionTable.erase(it);
        } else {
            ++it;
        }
    }
    trainingData.insert(trainingData.end(), tempInputs.begin(), tempInputs.end());
    trainingLabels.insert(trainingLabels.end(), tempLabels.begin(), tempLabels.end());
    Logger::log("Cleaned " + to_string(tempInputs.size()) + " expired connections.", Logger::INFO);
}

bool FirewallManager::addFirewallRule(const string &action, const string &direction,
                                     const string &source, const string &destination,
                                     const string &protocol) {
    string sAction = sanitizeShellArg(action);
    string sDirection = sanitizeShellArg(direction);
    string sSource = sanitizeShellArg(source);
    string sDestination = sanitizeShellArg(destination);
    string sProtocol = sanitizeShellArg(protocol);

    string rule = "rule family=\"ipv4\" " + sDirection + " source address=\"" +
                  sSource + "\" destination address=\"" + sDestination +
                  "\" service name=\"" + sProtocol + "\" " + sAction;
    string cmd = "firewall-cmd --permanent --add-rich-rule='" + rule + "'";
    string output = executeSystemCommand(cmd);
    executeSystemCommand("firewall-cmd --reload");
    if (output.find("success") != string::npos) {
        Logger::log("Added firewall rule: " + rule, Logger::INFO);
        return true;
    } else {
        Logger::log("Failed to add rule: " + output, Logger::ERROR);
        return false;
    }
}

bool FirewallManager::removeFirewallRule(const string &action, const string &direction,
                                        const string &source, const string &destination,
                                        const string &protocol) {
    string sAction = sanitizeShellArg(action);
    string sDirection = sanitizeShellArg(direction);
    string sSource = sanitizeShellArg(source);
    string sDestination = sanitizeShellArg(destination);
    string sProtocol = sanitizeShellArg(protocol);

    string rule = "rule family=\"ipv4\" " + sDirection + " source address=\"" +
                  sSource + "\" destination address=\"" + sDestination +
                  "\" service name=\"" + sProtocol + "\" " + sAction;
    string cmd = "firewall-cmd --permanent --remove-rich-rule='" + rule + "'";
    string output = executeSystemCommand(cmd);
    executeSystemCommand("firewall-cmd --reload");
    if (output.find("success") != string::npos) {
        Logger::log("Removed firewall rule: " + rule, Logger::INFO);
        return true;
    } else {
        Logger::log("Failed to remove rule: " + output, Logger::ERROR);
        return false;
    }
}

void FirewallManager::sendNotification(const string &title, const string &message) {
    string sTitle = sanitizeShellArg(title);
    string sMessage = sanitizeShellArg(message);
    string cmd = "notify-send \"" + sTitle + "\" \"" + sMessage + "\"";
    int status = system(cmd.c_str());
    if (status != 0) {
        Logger::log("Failed to send notification: " + sTitle, Logger::WARNING);
    } else {
        Logger::log("Notification sent: " + sTitle + " - " + sMessage, Logger::INFO);
    }
    sendWebhookPayload(title, message);
}

void FirewallManager::ruleViolationDetected(const string &rule, const string &violationDetail) {
    string msg = "Rule violation detected: " + rule + " - " + violationDetail;
    Logger::log(msg, Logger::WARNING);
    sendNotification("Firewall Violation", msg);
}

void FirewallManager::respondToThreat(const string &ip) {
    blockIPAddress(ip);
    sendNotification("Threat Detected", "Blocked suspicious IP: " + ip);
    ruleViolationDetected("Threat Response", "IP " + ip + " blocked.");
}

void FirewallManager::autoHeal() {
    if (detectThreat()) {
        blockAllTraffic();
        this_thread::sleep_for(chrono::seconds(30));
        unblockAllTraffic();
        rollbackRules();
    }
}

void FirewallManager::rollbackRules() {
    executeSystemCommand("firewall-cmd --reload");
    Logger::log("Firewall rules rolled back.", Logger::INFO);
    cout << "Firewall rules rolled back." << endl;
}

void FirewallManager::checkFirewallHealth() {
    string output = executeSystemCommand("firewall-cmd --state");
    if (output.find("running") == string::npos) {
        executeSystemCommand("systemctl restart firewalld");
        Logger::log("Firewall service restarted.", Logger::WARNING);
        cout << "Firewall service restarted." << endl;
    } else {
        Logger::log("Firewall is healthy.", Logger::INFO);
        cout << "Firewall is healthy." << endl;
    }
}

void FirewallManager::optimizeFirewallRules() {
    executeSystemCommand("firewall-cmd --permanent --remove-service=http");
    executeSystemCommand("firewall-cmd --reload");
    Logger::log("Firewall rules optimized.", Logger::INFO);
    cout << "Firewall rules optimized." << endl;
}

void FirewallManager::threatMonitor() {
    auto lastCheck = chrono::steady_clock::now();
    checkSchedules();
    while (running) {
        autoHeal();
        auto now = chrono::steady_clock::now();
        if (chrono::duration_cast<chrono::seconds>(now - lastCheck).count() >= 60) {
            checkSchedules();
            lastCheck = now;
        }
        this_thread::sleep_for(chrono::milliseconds(THREAT_CHECK_INTERVAL_MS));
    }
}

void FirewallManager::systemMaintenance() {
    while (running) {
        cleanupExpiredConnections();
        optimizeFirewallRules();
        checkFirewallHealth();
        Logger::rotateLogs();
        this_thread::sleep_for(chrono::milliseconds(MAINTENANCE_INTERVAL_MS));
    }
}

void FirewallManager::processPacket(const string &sourceIP, const string &sourcePort,
                                    const string &destIP, const string &destPort, int size,
                                    const string &protocol,
                                    double payloadEntropy, double flagAnomaly,
                                    const string &dnsQueryDomain,
                                    const string &payload) {
    string key = sourceIP + ":" + sourcePort + "->" + destIP + ":" + destPort;
    bool triggerThreatResponse = false;
    bool isBlocked = false;
    bool dnsBlocked = false;
    bool ipsBlocked = false;
    string ipsMsg = "";
    string status = "Allowed";

    // DPI protocol classification & stats recording
    std::string appProtocol = protocol; 
    std::string appDetail = "";

    {
        lock_guard<mutex> lock(globalMutex);

        isBlocked = (blockedIPs.count(sourceIP) > 0) || threatSync->isThreatIP(sourceIP);

        // Captive Portal interception check
        if (!isBlocked && captivePortalEnabled && captivePortal) {
            if (destPort != "8082" && sourcePort != "8082" && !captivePortal->isClientAuthenticated(sourceIP)) {
                isBlocked = true;
                status = "Blocked (Captive Portal Redirect)";
            }
        }

        // IPS signature check
        if (!isBlocked && ipsEngine) {
            IpsRule matchedRule;
            int sPort = 0;
            int dPort = 0;
            try { sPort = std::stoi(sourcePort); } catch(...) {}
            try { dPort = std::stoi(destPort); } catch(...) {}
            if (ipsEngine->inspectPacket(protocol, sourceIP, sPort, destIP, dPort, payload, matchedRule)) {
                ipsMsg = matchedRule.message;
                if (matchedRule.action == "drop") {
                    ipsBlocked = true;
                    isBlocked = true;
                    triggerThreatResponse = true;
                } else {
                    status = "Flagged";
                }
                sendNotification("IPS Signature Triggered", "Rule " + to_string(matchedRule.sid) + ": " + matchedRule.message + " from " + sourceIP);
            }
        }

        // DPI processing
        if (dpiClassifier) {
            int dPort = 0;
            try { dPort = std::stoi(destPort); } catch(...) {}
            appProtocol = dpiClassifier->classifyPayload(payload, dPort, appDetail);
            dpiClassifier->recordTraffic(appProtocol, size);
        }

        // DNS Sinkhole check
        if (!dnsQueryDomain.empty() && dnsSinkholeEnabled) {
            bool found = (blockedDomains.count(dnsQueryDomain) > 0);
            if (!found) {
                string cat = getDomainCategory(dnsQueryDomain);
                if (!cat.empty() && categorySchedules.count(cat) > 0 && categorySchedules[cat].isCurrentlyBlocked) {
                    found = true;
                }
            }
            if (found) {
                dnsBlocked = true;
                isBlocked = true;
                triggerThreatResponse = true;
            }
        }

        auto &count = ipConnectionCounts[sourceIP];
        count++;

        if (count > CONNECTION_THRESHOLD) {
            triggerThreatResponse = true;
            isBlocked = true;
        }

        if (connectionTable.find(key) == connectionTable.end()) {
            connectionTable[key] = {"NEW",      sourceIP, destIP,
                                    sourcePort, destPort, chrono::system_clock::now(),
                                    1,          size,     isBlocked,
                                    payloadEntropy, flagAnomaly};
        } else {
            auto &conn = connectionTable[key];
            conn.packetCount++;
            conn.totalBytes += size;
            conn.lastUpdate = chrono::system_clock::now();
            conn.accumulatedEntropy += payloadEntropy;
            conn.accumulatedAnomalies += flagAnomaly;
            if (isBlocked) {
                conn.wasBlocked = true;
            }
        }

        if (size > AVERAGE_PACKET_SIZE * PACKET_SIZE_MULTIPLIER) {
            Logger::log("Large packet anomaly from " + sourceIP, Logger::WARNING);
            triggerThreatResponse = true;
            isBlocked = true;
        }

        if (!isBlocked) {
            NetworkFeatures f = extractFeatures(connectionTable[key]);
            vector<double> input = convertToVector(f);
            neuralNetwork->forwardPropagate(input);
            if (neuralNetwork->detectThreat()) {
                triggerThreatResponse = true;
                isBlocked = true;
                connectionTable[key].wasBlocked = true;
            }
        }

        // Port Knocking check
        try {
            int dPort = std::stoi(destPort);
            checkPortKnock(sourceIP, dPort);
        } catch (...) {}

        if (isBlocked) {
            if (dnsBlocked) {
                status = "Blocked (DNS: " + dnsQueryDomain + ")";
            } else if (ipsBlocked) {
                status = "Blocked (IPS: " + ipsMsg + ")";
            } else if (status == "Blocked (Captive Portal Redirect)") {
                // Keep Captive Portal redirect status
            } else {
                status = "Blocked";
            }
        } else if (status == "Flagged" || flagAnomaly > 0.0 || payloadEntropy > 0.7) {
            status = "Flagged";
        } else {
            status = "Allowed";
        }

        auto now = chrono::system_clock::now();
        time_t tt = chrono::system_clock::to_time_t(now);
        tm local_tm;
        char time_buf[64] = {0};
        if (localtime_r(&tt, &local_tm) != nullptr) {
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &local_tm);
        } else {
            strcpy(time_buf, "Unknown");
        }

        LivePacketRecord record;
        record.timestamp = time_buf;
        
        // Show protocol with detailed info if available
        if (!appDetail.empty() && appProtocol != "Unknown") {
            record.protocol = appProtocol + " (" + appDetail + ")";
        } else {
            record.protocol = appProtocol;
        }

        record.sourceIP = sourceIP;
        record.sourcePort = sourcePort;
        record.destIP = destIP;
        record.destPort = destPort;
        record.size = size;
        record.status = status;

        recentPackets.push_back(record);
        if (recentPackets.size() > 100) {
            recentPackets.erase(recentPackets.begin());
        }
    }

    if (triggerThreatResponse) {
        respondToThreat(sourceIP);
    }
}

std::vector<LivePacketRecord> FirewallManager::getRecentPackets() {
    lock_guard<mutex> lock(globalMutex);
    return recentPackets;
}

void FirewallManager::clearRecentPackets() {
    lock_guard<mutex> lock(globalMutex);
    recentPackets.clear();
}

void FirewallManager::checkPortKnock(const string &sourceIP, int destPort) {
    auto it = std::find(knockSequence.begin(), knockSequence.end(), destPort);
    if (it == knockSequence.end()) {
        return;
    }
    
    int index = std::distance(knockSequence.begin(), it);
    auto now = std::chrono::steady_clock::now();
    auto &state = knockStates[sourceIP];
    
    if (state.currentStep > 0) {
        double elapsed = std::chrono::duration<double>(now - state.lastKnockTime).count();
        if (elapsed > knockWindowSeconds) {
            state.currentStep = 0;
        }
    }
    
    if (index == 0) {
        state.currentStep = 1;
        state.lastKnockTime = now;
        Logger::log("Port knock stage 1/3 from " + sourceIP + " on port " + to_string(destPort), Logger::INFO);
    } else if (index == 1 && state.currentStep == 1) {
        state.currentStep = 2;
        state.lastKnockTime = now;
        Logger::log("Port knock stage 2/3 from " + sourceIP + " on port " + to_string(destPort), Logger::INFO);
    } else if (index == 2 && state.currentStep == 2) {
        state.currentStep = 3;
        state.lastKnockTime = now;
        Logger::log("Port knock stage 3/3 complete from " + sourceIP + "! Opening port " + to_string(knockTargetPort), Logger::WARNING);
        
        string ipCopy = sourceIP;
        int portCopy = knockTargetPort;
        std::thread([this, ipCopy, portCopy]() {
            openPortForIP(ipCopy, portCopy);
        }).detach();
        
        state.currentStep = 0;
    } else {
        state.currentStep = 0;
    }
}

void FirewallManager::openPortForIP(const string &ip, int port) {
    string cmd = "firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"" +
                 ip + "\" port port=\"" + to_string(port) + "\" protocol=\"tcp\" accept'";
    executeSystemCommand(cmd);
    executeSystemCommand("firewall-cmd --reload");
    Logger::log("Authorized port knock access. Opened port " + to_string(port) + " for IP " + ip, Logger::WARNING);
    
    int duration = knockOpenDurationSeconds;
    std::thread([this, ip, port, duration]() {
        std::this_thread::sleep_for(std::chrono::seconds(duration));
        closePortForIP(ip, port);
    }).detach();
}

void FirewallManager::closePortForIP(const string &ip, int port) {
    string cmd = "firewall-cmd --permanent --remove-rich-rule='rule family=\"ipv4\" source address=\"" +
                 ip + "\" port port=\"" + to_string(port) + "\" protocol=\"tcp\" accept'";
    executeSystemCommand(cmd);
    executeSystemCommand("firewall-cmd --reload");
    Logger::log("Port knock authorization expired. Closed port " + to_string(port) + " for IP " + ip, Logger::INFO);
}

void FirewallManager::setKnockConfig(const std::vector<int>& seq, int window, int target, int duration) {
    lock_guard<mutex> lock(globalMutex);
    knockSequence = seq;
    knockWindowSeconds = window;
    knockTargetPort = target;
    knockOpenDurationSeconds = duration;
    saveConfig();
}

void FirewallManager::blockWebsite(const string &website) {
    blockDomain(website);
}

void FirewallManager::trainNeuralNetwork() {
    if (trainingData.size() > MAX_TRAINING_SAMPLES &&
        trainingData.size() == trainingLabels.size()) {
        neuralNetwork->train(trainingData, trainingLabels, EPOCHS, LEARNING_RATE);
        trainingData.clear();
        trainingLabels.clear();
        neuralNetwork->saveModel(MODEL_FILE);
    } else {
        Logger::log("Insufficient samples for training: " + to_string(trainingData.size()),
                    Logger::WARNING);
    }
}

void FirewallManager::restoreDefaultConfig() {
    executeSystemCommand("firewall-cmd --complete-reload");
    blockedIPs.clear();
    blockedDomains.clear();
    saveBlockedIPs();
    saveBlockedDomains();
    Logger::log("Restored default firewall configuration.", Logger::INFO);
}

string FirewallManager::getStatus() {
    stringstream ss;
    ss << "Panic mode: " << (panicModeEnabled ? "Enabled" : "Disabled") << endl;
    ss << "Internet: " << (internetStatus ? "Connected" : "Disconnected") << endl;
    ss << "VPN: " << (isVpnConnected() ? "Connected" : "Disconnected") << endl;
    ss << "Blocked IPs: " << blockedIPs.size() << endl;
    ss << "Blocked Domains: " << blockedDomains.size() << endl;
    return ss.str();
}

bool FirewallManager::detectThreat() {
    lock_guard<mutex> lock(globalMutex);
    for (const auto &pair : connectionTable) {
        NetworkFeatures f = extractFeatures(pair.second);
        vector<double> input = convertToVector(f);
        neuralNetwork->forwardPropagate(input);
        if (neuralNetwork->detectThreat() ||
            threatSync->isThreatIP(pair.second.sourceIP) ||
            threatIntel.isThreatIP(pair.second.sourceIP)) {
            return true;
        }
    }
    return false;
}

void FirewallManager::runCLI() {
    if (!isatty(STDIN_FILENO)) {
        string command;
        while (running && getline(cin, command)) {
            if (command.empty())
                continue;
            istringstream iss(command);
            string cmd;
            iss >> cmd;
            if (cmd == "exit")
                break;
            else if (cmd == "help") {
                string category;
                iss >> category;
                cout << getHelpInformation(category) << endl;
            } else if (cmd == "block-ip") {
                string ip;
                iss >> ip;
                if (ip.empty())
                    cout << "Usage: block-ip <ip>" << endl;
                else
                    blockIPAddress(ip);
            } else if (cmd == "unblock-ip") {
                string ip;
                iss >> ip;
                if (ip.empty())
                    cout << "Usage: unblock-ip <ip>" << endl;
                else
                    unblockIPAddress(ip);
            } else if (cmd == "panic") {
                blockAllTraffic();
            } else if (cmd == "check-internet") {
                checkInternetConnectivity();
            } else if (cmd == "geoip") {
                string ip;
                iss >> ip;
                if (ip.empty())
                    cout << "Usage: geoip <ip>" << endl;
                else
                    getGeoIP(ip);
            } else if (cmd == "block-website") {
                string site;
                iss >> site;
                if (site.empty())
                    cout << "Usage: block-website <domain>" << endl;
                else
                    blockWebsite(site);
            } else if (cmd == "block-domain") {
                string domain, category;
                iss >> domain >> category;
                if (domain.empty())
                    cout << "Usage: block-domain <domain> [category]" << endl;
                else
                    blockDomain(domain, category);
            } else if (cmd == "unblock-domain") {
                string domain;
                iss >> domain;
                if (domain.empty())
                    cout << "Usage: unblock-domain <domain>" << endl;
                else
                    unblockDomain(domain);
            } else if (cmd == "block-category") {
                string category;
                iss >> category;
                if (category.empty())
                    cout << "Usage: block-category <category>" << endl;
                else
                    blockCategory(category);
            } else if (cmd == "unblock-category") {
                string category;
                iss >> category;
                if (category.empty())
                    cout << "Usage: unblock-category <category>" << endl;
                else
                    unblockCategory(category);
            } else if (cmd == "train") {
                trainNeuralNetwork();
            } else if (cmd == "restore-default") {
                restoreDefaultConfig();
            } else if (cmd == "add-port") {
                string port, protocol;
                iss >> port >> protocol;
                if (port.empty() || protocol.empty())
                    cout << "Usage: add-port <port> <protocol>" << endl;
                else
                    addFirewallRule("accept", "in", "0.0.0.0/0", port, protocol);
            } else if (cmd == "remove-port") {
                string port, protocol;
                iss >> port >> protocol;
                if (port.empty() || protocol.empty())
                    cout << "Usage: remove-port <port> <protocol>" << endl;
                else
                    removeFirewallRule("accept", "in", "0.0.0.0/0", port, protocol);
            } else if (cmd == "connect-vpn") {
                string config;
                iss >> config;
                if (config.empty())
                    cout << "Usage: connect-vpn <config_path>" << endl;
                else
                    connectToVpn(config);
            } else if (cmd == "disconnect-vpn") {
                disconnectVpn();
            } else if (cmd == "status") {
                cout << getStatus();
            } else if (cmd == "export-blocked-ips") {
                string filename;
                iss >> filename;
                if (filename.empty())
                    cout << "Usage: export-blocked-ips <filename>" << endl;
                else
                    exportBlockedIPsToCSV(filename);
            } else if (cmd == "add-nat") {
                string sourceIP, destIP, port;
                iss >> sourceIP >> destIP >> port;
                if (sourceIP.empty() || destIP.empty() || port.empty())
                    cout << "Usage: add-nat <sourceIP> <destIP> <port>" << endl;
                else
                    addNatRule(sourceIP, destIP, port);
            } else if (cmd == "remove-nat") {
                string ruleID;
                getline(iss, ruleID);
                ruleID.erase(0, ruleID.find_first_not_of(" \t"));
                if (ruleID.empty())
                    cout << "Usage: remove-nat <ruleID>" << endl;
                else
                    removeNatRule(ruleID);
            } else if (cmd == "block-all") {
                blockAllTraffic();
            } else if (cmd == "unblock-all") {
                unblockAllTraffic();
            } else if (cmd == "send-notification") {
                string title, message;
                iss >> title;
                getline(iss, message);
                message.erase(0, message.find_first_not_of(" \t"));
                if (title.empty() || message.empty())
                    cout << "Usage: send-notification <title> <message>" << endl;
                else
                    sendNotification(title, message);
            } else if (cmd == "rule-violation") {
                string rule, detail;
                iss >> rule;
                getline(iss, detail);
                detail.erase(0, detail.find_first_not_of(" \t"));
                if (rule.empty() || detail.empty())
                    cout << "Usage: rule-violation <rule> <detail>" << endl;
                else
                    ruleViolationDetected(rule, detail);
            } else if (cmd == "detect-threat") {
                cout << "Threat detected: " << (detectThreat() ? "Yes" : "No") << endl;
            } else if (cmd == "respond-threat") {
                string ip;
                iss >> ip;
                if (ip.empty())
                    cout << "Usage: respond-threat <ip>" << endl;
                else
                    respondToThreat(ip);
            } else if (cmd == "train-adaptive") {
                cout << "Training adaptive model requires traffic data (not implemented for manual input)." << endl;
            } else if (cmd == "auto-heal") {
                autoHeal();
            } else if (cmd == "rollback") {
                rollbackRules();
            } else if (cmd == "check-health") {
                checkFirewallHealth();
            } else if (cmd == "optimize") {
                optimizeFirewallRules();
            } else if (cmd == "cleanup-connections") {
                cleanupExpiredConnections();
            } else if (cmd == "set-log-level") {
                string level;
                iss >> level;
                if (level == "INFO")
                    Logger::setLevel(Logger::INFO);
                else if (level == "WARNING")
                    Logger::setLevel(Logger::WARNING);
                else if (level == "ERROR")
                    Logger::setLevel(Logger::ERROR);
                else if (level == "DEBUG")
                    Logger::setLevel(Logger::DEBUG);
                else
                    cout << "Usage: set-log-level <INFO|WARNING|ERROR|DEBUG>" << endl;
            } else if (cmd == "rotate-logs") {
                Logger::rotateLogs();
            } else if (cmd == "log-message") {
                string level, message;
                iss >> level;
                getline(iss, message);
                message.erase(0, message.find_first_not_of(" \t"));
                if (level.empty() || message.empty())
                    cout << "Usage: log-message <INFO|WARNING|ERROR|DEBUG> <message>" << endl;
                else {
                    if (level == "INFO")
                        Logger::log(message, Logger::INFO);
                    else if (level == "WARNING")
                        Logger::log(message, Logger::WARNING);
                    else if (level == "ERROR")
                        Logger::log(message, Logger::ERROR);
                    else if (level == "DEBUG")
                        Logger::log(message, Logger::DEBUG);
                    else
                        cout << "Invalid log level." << endl;
                }
            } else {
                cout << "Unknown command. Type 'help' for list of categories." << endl;
            }
        }
        return;
    }
    rl_attempted_completion_function = firewall_completion;
    char *input;
    cout << "YUNA Firewall CLI - Type 'help' for commands." << endl;
    while (running && (input = readline("> "))) {
        if (!input)
            break;
        string command(input);
        free(input);
        if (command.empty())
            continue;
        add_history(command.c_str());
        istringstream iss(command);
        string cmd;
        iss >> cmd;
        if (cmd == "exit")
            break;
        else if (cmd == "help") {
            string category;
            iss >> category;
            cout << getHelpInformation(category) << endl;
        } else if (cmd == "block-ip") {
            string ip;
            iss >> ip;
            if (ip.empty())
                cout << "Usage: block-ip <ip>" << endl;
            else
                blockIPAddress(ip);
        } else if (cmd == "unblock-ip") {
            string ip;
            iss >> ip;
            if (ip.empty())
                cout << "Usage: unblock-ip <ip>" << endl;
            else
                unblockIPAddress(ip);
        } else if (cmd == "panic") {
            blockAllTraffic();
        } else if (cmd == "check-internet") {
            checkInternetConnectivity();
        } else if (cmd == "geoip") {
            string ip;
            iss >> ip;
            if (ip.empty())
                cout << "Usage: geoip <ip>" << endl;
            else
                getGeoIP(ip);
        } else if (cmd == "block-website") {
            string site;
            iss >> site;
            if (site.empty())
                cout << "Usage: block-website <domain>" << endl;
            else
                blockWebsite(site);
        } else if (cmd == "block-domain") {
            string domain, category;
            iss >> domain >> category;
            if (domain.empty())
                cout << "Usage: block-domain <domain> [category]" << endl;
            else
                blockDomain(domain, category);
        } else if (cmd == "unblock-domain") {
            string domain;
            iss >> domain;
            if (domain.empty())
                cout << "Usage: unblock-domain <domain>" << endl;
            else
                unblockDomain(domain);
        } else if (cmd == "block-category") {
            string category;
            iss >> category;
            if (category.empty())
                cout << "Usage: block-category <category>" << endl;
            else
                blockCategory(category);
        } else if (cmd == "unblock-category") {
            string category;
            iss >> category;
            if (category.empty())
                cout << "Usage: unblock-category <category>" << endl;
            else
                unblockCategory(category);
        } else if (cmd == "train") {
            trainNeuralNetwork();
        } else if (cmd == "restore-default") {
            restoreDefaultConfig();
        } else if (cmd == "add-port") {
            string port, protocol;
            iss >> port >> protocol;
            if (port.empty() || protocol.empty())
                cout << "Usage: add-port <port> <protocol>" << endl;
            else
                addFirewallRule("accept", "in", "0.0.0.0/0", port, protocol);
        } else if (cmd == "remove-port") {
            string port, protocol;
            iss >> port >> protocol;
            if (port.empty() || protocol.empty())
                cout << "Usage: remove-port <port> <protocol>" << endl;
            else
                removeFirewallRule("accept", "in", "0.0.0.0/0", port, protocol);
        } else if (cmd == "connect-vpn") {
            string config;
            iss >> config;
            if (config.empty())
                cout << "Usage: connect-vpn <config_path>" << endl;
            else
                connectToVpn(config);
        } else if (cmd == "disconnect-vpn") {
            disconnectVpn();
        } else if (cmd == "status") {
            cout << getStatus();
        } else if (cmd == "export-blocked-ips") {
            string filename;
            iss >> filename;
            if (filename.empty())
                cout << "Usage: export-blocked-ips <filename>" << endl;
            else
                exportBlockedIPsToCSV(filename);
        } else if (cmd == "add-nat") {
            string sourceIP, destIP, port;
            iss >> sourceIP >> destIP >> port;
            if (sourceIP.empty() || destIP.empty() || port.empty())
                cout << "Usage: add-nat <sourceIP> <destIP> <port>" << endl;
            else
                addNatRule(sourceIP, destIP, port);
        } else if (cmd == "remove-nat") {
            string ruleID;
            getline(iss, ruleID);
            ruleID.erase(0, ruleID.find_first_not_of(" \t"));
            if (ruleID.empty())
                cout << "Usage: remove-nat <ruleID>" << endl;
            else
                removeNatRule(ruleID);
        } else if (cmd == "block-all") {
            blockAllTraffic();
        } else if (cmd == "unblock-all") {
            unblockAllTraffic();
        } else if (cmd == "send-notification") {
            string title, message;
            iss >> title;
            getline(iss, message);
            message.erase(0, message.find_first_not_of(" \t"));
            if (title.empty() || message.empty())
                cout << "Usage: send-notification <title> <message>" << endl;
            else
                sendNotification(title, message);
        } else if (cmd == "rule-violation") {
            string rule, detail;
            iss >> rule;
            getline(iss, detail);
            detail.erase(0, detail.find_first_not_of(" \t"));
            if (rule.empty() || detail.empty())
                cout << "Usage: rule-violation <rule> <detail>" << endl;
            else
                ruleViolationDetected(rule, detail);
        } else if (cmd == "detect-threat") {
            cout << "Threat detected: " << (detectThreat() ? "Yes" : "No") << endl;
        } else if (cmd == "respond-threat") {
            string ip;
            iss >> ip;
            if (ip.empty())
                cout << "Usage: respond-threat <ip>" << endl;
            else
                respondToThreat(ip);
        } else if (cmd == "train-adaptive") {
            cout << "Training adaptive model requires traffic data (not implemented for manual input)." << endl;
        } else if (cmd == "auto-heal") {
            autoHeal();
        } else if (cmd == "rollback") {
            rollbackRules();
        } else if (cmd == "check-health") {
            checkFirewallHealth();
        } else if (cmd == "optimize") {
            optimizeFirewallRules();
        } else if (cmd == "cleanup-connections") {
            cleanupExpiredConnections();
        } else if (cmd == "set-log-level") {
            string level;
            iss >> level;
            if (level == "INFO")
                Logger::setLevel(Logger::INFO);
            else if (level == "WARNING")
                Logger::setLevel(Logger::WARNING);
            else if (level == "ERROR")
                Logger::setLevel(Logger::ERROR);
            else if (level == "DEBUG")
                Logger::setLevel(Logger::DEBUG);
            else
                cout << "Usage: set-log-level <INFO|WARNING|ERROR|DEBUG>" << endl;
        } else if (cmd == "rotate-logs") {
            Logger::rotateLogs();
        } else if (cmd == "log-message") {
            string level, message;
            iss >> level;
            getline(iss, message);
            message.erase(0, message.find_first_not_of(" \t"));
            if (level.empty() || message.empty())
                cout << "Usage: log-message <INFO|WARNING|ERROR|DEBUG> <message>" << endl;
            else {
                if (level == "INFO")
                    Logger::log(message, Logger::INFO);
                else if (level == "WARNING")
                    Logger::log(message, Logger::WARNING);
                else if (level == "ERROR")
                    Logger::log(message, Logger::ERROR);
                else if (level == "DEBUG")
                    Logger::log(message, Logger::DEBUG);
                else
                    cout << "Invalid log level." << endl;
            }
        } else {
            cout << "Unknown command. Type 'help' for list of categories." << endl;
        }
    }
    rl_free_line_state();
    rl_cleanup_after_signal();
}

void FirewallManager::loadConfig() {
    ifstream file(CONFIG_FILE);
    if (!file.is_open()) {
        Logger::log("No config file found.", Logger::INFO);
        return;
    }
    json j;
    try {
        file >> j;
        if (j.contains("webhook_url") && j["webhook_url"].is_string()) {
            webhookUrl = j["webhook_url"].get<string>();
        }
        if (j.contains("schedules") && j["schedules"].is_object()) {
            for (auto it = j["schedules"].begin(); it != j["schedules"].end(); ++it) {
                CategorySchedule sched;
                sched.startHour = it.value()["startHour"].get<int>();
                sched.endHour = it.value()["endHour"].get<int>();
                sched.enabled = it.value()["enabled"].get<bool>();
                sched.isCurrentlyBlocked = it.value().contains("isCurrentlyBlocked") ? it.value()["isCurrentlyBlocked"].get<bool>() : false;
                categorySchedules[it.key()] = sched;
            }
        }
        if (j.contains("knock_sequence") && j["knock_sequence"].is_array()) {
            knockSequence.clear();
            for (const auto &val : j["knock_sequence"]) {
                knockSequence.push_back(val.get<int>());
            }
        }
        if (j.contains("knock_window") && j["knock_window"].is_number()) {
            knockWindowSeconds = j["knock_window"].get<int>();
        }
        if (j.contains("knock_target") && j["knock_target"].is_number()) {
            knockTargetPort = j["knock_target"].get<int>();
        }
        if (j.contains("knock_duration") && j["knock_duration"].is_number()) {
            knockOpenDurationSeconds = j["knock_duration"].get<int>();
        }
        if (j.contains("dns_sinkhole_enabled") && j["dns_sinkhole_enabled"].is_bool()) {
            dnsSinkholeEnabled = j["dns_sinkhole_enabled"].get<bool>();
        }
        if (j.contains("captive_portal_enabled") && j["captive_portal_enabled"].is_bool()) {
            captivePortalEnabled = j["captive_portal_enabled"].get<bool>();
        }
        Logger::log("Configuration loaded.", Logger::INFO);
    } catch (const exception &e) {
        Logger::log("Error loading config: " + string(e.what()), Logger::ERROR);
    }
    file.close();
}

void FirewallManager::saveConfig() {
    json j;
    j["webhook_url"] = webhookUrl;
    json scheds;
    for (const auto &pair : categorySchedules) {
        json s;
        s["startHour"] = pair.second.startHour;
        s["endHour"] = pair.second.endHour;
        s["enabled"] = pair.second.enabled;
        s["isCurrentlyBlocked"] = pair.second.isCurrentlyBlocked;
        scheds[pair.first] = s;
    }
    j["schedules"] = scheds;
    j["knock_sequence"] = knockSequence;
    j["knock_window"] = knockWindowSeconds;
    j["knock_target"] = knockTargetPort;
    j["knock_duration"] = knockOpenDurationSeconds;
    j["dns_sinkhole_enabled"] = dnsSinkholeEnabled;
    j["captive_portal_enabled"] = captivePortalEnabled;

    ofstream file(CONFIG_FILE);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
        Logger::log("Configuration saved.", Logger::INFO);
    } else {
        Logger::log("Failed to save config.", Logger::ERROR);
    }
}

void FirewallManager::sendWebhookPayload(const string &title, const string &message) {
    if (webhookUrl.empty()) return;
    string urlCopy = webhookUrl;
    thread([urlCopy, title, message]() {
        CURL* localCurl = curl_easy_init();
        if (!localCurl) return;

        nlohmann::json payload;
        payload["content"] = "**[YUNA Firewall - " + title + "]** " + message;
        string jsonStr = payload.dump();

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(localCurl, CURLOPT_URL, urlCopy.c_str());
        curl_easy_setopt(localCurl, CURLOPT_POST, 1L);
        curl_easy_setopt(localCurl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(localCurl, CURLOPT_POSTFIELDS, jsonStr.c_str());
        curl_easy_setopt(localCurl, CURLOPT_TIMEOUT, 5L);

        CURLcode res = curl_easy_perform(localCurl);
        if (res != CURLE_OK) {
            Logger::log("Webhook notify failed: " + string(curl_easy_strerror(res)), Logger::ERROR);
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(localCurl);
    }).detach();
}

void FirewallManager::checkSchedules() {
    auto now = chrono::system_clock::now();
    time_t tt = chrono::system_clock::to_time_t(now);
    tm local_tm;
    if (localtime_r(&tt, &local_tm) == nullptr) return;
    int currentHour = local_tm.tm_hour;

    vector<string> categoriesToBlock;
    vector<string> categoriesToUnblock;

    {
        lock_guard<mutex> lock(globalMutex);
        for (auto &pair : categorySchedules) {
            CategorySchedule &sched = pair.second;
            if (!sched.enabled) {
                if (sched.isCurrentlyBlocked) {
                    categoriesToUnblock.push_back(pair.first);
                    sched.isCurrentlyBlocked = false;
                }
                continue;
            }

            bool shouldBeBlocked = false;
            if (sched.startHour <= sched.endHour) {
                shouldBeBlocked = (currentHour >= sched.startHour && currentHour < sched.endHour);
            } else {
                shouldBeBlocked = (currentHour >= sched.startHour || currentHour < sched.endHour);
            }

            if (shouldBeBlocked && !sched.isCurrentlyBlocked) {
                categoriesToBlock.push_back(pair.first);
                sched.isCurrentlyBlocked = true;
            } else if (!shouldBeBlocked && sched.isCurrentlyBlocked) {
                categoriesToUnblock.push_back(pair.first);
                sched.isCurrentlyBlocked = false;
            }
        }
    }

    for (const auto &cat : categoriesToBlock) {
        blockCategory(cat);
    }
    for (const auto &cat : categoriesToUnblock) {
        unblockCategory(cat);
    }
}

void FirewallManager::setCategorySchedule(const string &category, int start, int end, bool enabled) {
    lock_guard<mutex> lock(globalMutex);
    CategorySchedule sched;
    sched.startHour = start;
    sched.endHour = end;
    sched.enabled = enabled;
    sched.isCurrentlyBlocked = categorySchedules.count(category) ? categorySchedules[category].isCurrentlyBlocked : false;
    categorySchedules[category] = sched;
    saveConfig();
}

string FirewallManager::getCurrentMacAddress() {
    ifstream file("/sys/class/net/" + interfaceName + "/address");
    if (!file.is_open()) {
        return "00:00:00:00:00:00";
    }
    string mac;
    file >> mac;
    file.close();
    return mac;
}

string FirewallManager::generateRandomMacAddress() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    
    stringstream ss;
    ss << "02"; // Locally administered unicast prefix
    for (int i = 0; i < 5; ++i) {
        int val = dis(gen);
        ss << ":" << std::setfill('0') << std::setw(2) << std::hex << val;
    }
    return ss.str();
}

bool FirewallManager::setMacAddress(const string& macAddress) {
    regex macRegex("^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$");
    if (!regex_match(macAddress, macRegex)) {
        Logger::log("Invalid MAC address format: " + macAddress, Logger::ERROR);
        return false;
    }
    
    Logger::log("Stopping packet sniffer on " + interfaceName + " to modify MAC address...", Logger::INFO);
    sniffer.stop();
    
    string sInterface = sanitizeShellArg(interfaceName);
    string sMac = sanitizeShellArg(macAddress);
    
    executeSystemCommand("ip link set dev " + sInterface + " down");
    string out = executeSystemCommand("ip link set dev " + sInterface + " address " + sMac);
    executeSystemCommand("ip link set dev " + sInterface + " up");
    
    if (!out.empty()) {
        Logger::log("MAC Spoof Output: " + out, Logger::INFO);
    }
    
    Logger::log("Restarting packet sniffer on " + interfaceName + "...", Logger::INFO);
    bool startRes = sniffer.start();
    if (!startRes) {
        Logger::log("Failed to restart sniffer after MAC update.", Logger::ERROR);
    }
    
    string verifiedMac = getCurrentMacAddress();
    if (verifiedMac == macAddress) {
        Logger::log("MAC address successfully updated to " + macAddress, Logger::WARNING);
        return true;
    } else {
        Logger::log("MAC address update failed. Current: " + verifiedMac, Logger::ERROR);
        return false;
    }
}
