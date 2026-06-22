#ifndef QOS_MANAGER_H
#define QOS_MANAGER_H

#include <string>
#include <vector>
#include <mutex>

struct QosRule {
    std::string id;          // Unique ID
    std::string type;        // "ip" or "port"
    std::string value;       // IP address or port number
    std::string direction;   // "src" or "dst" (only for type "ip")
    std::string rate;        // e.g. "10mbit", "512kbps"
    int classId;             // HTB class ID (e.g. 10, 11...)
};

class QosManager {
private:
    std::string interfaceName;
    std::vector<QosRule> rules;
    std::mutex qosMutex;
    int nextClassId;

    void loadRulesConfig();
    void saveRulesConfig();
    std::string executeSystemCommand(const std::string& cmd);
    void initQdisc();
    void clearSystemQdisc();

public:
    QosManager(const std::string& interface);
    ~QosManager();

    bool addRule(const std::string& type, const std::string& value, const std::string& direction, const std::string& rate);
    bool removeRule(const std::string& id);
    std::vector<QosRule> getRules();
    void clearRules();
    void reapplyAllRules();
    
    std::string getInterfaceName() const { return interfaceName; }
};

#endif // QOS_MANAGER_H
