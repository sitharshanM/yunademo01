#ifndef CAPTIVE_PORTAL_H
#define CAPTIVE_PORTAL_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>

class FirewallManager;

struct PortalUser {
    std::string username;
    std::string password; // Plaintext or hash for credentials check
    std::string role = "user";
};

struct ActiveSession {
    std::string ip;
    std::string username;
    std::string loginTime;
    unsigned long long bytesTransferred = 0;
};

class CaptivePortal {
private:
    FirewallManager* manager;
    std::vector<PortalUser> users;
    std::vector<ActiveSession> sessions;
    std::mutex portalMutex;
    std::thread serverThread;
    std::atomic<bool> running;
    int serverPort;
    std::string usersFilePath;
    int serverSocket;

    void loadUsers();
    void saveUsers();
    void runServerLoop();
    std::string getCurrentTimestamp();
    void handleClientConnection(int clientSocket, const std::string& clientIp);

public:
    explicit CaptivePortal(FirewallManager* mgr);
    ~CaptivePortal();

    bool startPortalServer(int port = 8082);
    void stopPortalServer();
    bool isServerRunning() const { return running.load(); }

    bool authenticateClient(const std::string& ip, const std::string& username, const std::string& password);
    void revokeClient(const std::string& ip);
    bool isClientAuthenticated(const std::string& ip);

    bool addUser(const std::string& username, const std::string& password);
    bool removeUser(const std::string& username);
    std::vector<PortalUser> getUsers();
    std::vector<ActiveSession> getSessions();
};

#endif // CAPTIVE_PORTAL_H
