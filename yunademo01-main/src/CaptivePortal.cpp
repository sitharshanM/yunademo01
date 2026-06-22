#include "CaptivePortal.h"
#include "FirewallManager.h"
#include "Logger.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <iostream>
#include <ctime>
#include <algorithm>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close_socket(s) closesocket(s)
    #define read_socket(s, b, l) recv(s, b, l, 0)
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/select.h>
    #define close_socket(s) ::close(s)
    #define read_socket(s, b, l) ::read(s, b, l)
#endif

using json = nlohmann::json;

#define PORTAL_USERS_FILE "portal_users.json"

CaptivePortal::CaptivePortal(FirewallManager* mgr)
    : manager(mgr), running(false), serverPort(8082), usersFilePath(PORTAL_USERS_FILE), serverSocket(-1) {
    loadUsers();
    
    // Create default admin user if database is empty
    if (users.empty()) {
        PortalUser admin;
        admin.username = "admin";
        admin.password = "admin123";
        admin.role = "admin";
        users.push_back(admin);
        saveUsers();
    }
}

CaptivePortal::~CaptivePortal() {
    stopPortalServer();
}

std::string CaptivePortal::getCurrentTimestamp() {
    std::time_t now = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buf);
}

void CaptivePortal::loadUsers() {
    std::ifstream file(usersFilePath);
    if (!file.is_open()) return;
    json j;
    try {
        file >> j;
        if (j.contains("users") && j["users"].is_array()) {
            users.clear();
            for (const auto& item : j["users"]) {
                PortalUser user;
                user.username = item.value("username", "");
                user.password = item.value("password", "");
                user.role = item.value("role", "user");
                users.push_back(user);
            }
        }
    } catch (...) {}
    file.close();
}

void CaptivePortal::saveUsers() {
    json j;
    json userList = json::array();
    for (const auto& user : users) {
        json item;
        item["username"] = user.username;
        item["password"] = user.password;
        item["role"] = user.role;
        userList.push_back(item);
    }
    j["users"] = userList;
    std::ofstream file(usersFilePath);
    if (file.is_open()) {
        file << j.dump(4);
        file.close();
    }
}

bool CaptivePortal::startPortalServer(int port) {
    if (running.load()) return true;
    serverPort = port;
    running = true;
    
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        Logger::log("Captive Portal: WSAStartup failed.", Logger::ERROR);
        running = false;
        return false;
    }
#endif

    serverThread = std::thread(&CaptivePortal::runServerLoop, this);
    Logger::log("Captive Portal: Started background HTTP redirect server on port " + std::to_string(port), Logger::INFO);
    return true;
}

void CaptivePortal::stopPortalServer() {
    if (!running.load()) return;
    running = false;
    
    if (serverSocket >= 0) {
        close_socket(serverSocket);
        serverSocket = -1;
    }
    
    if (serverThread.joinable()) {
        serverThread.join();
    }

#ifdef _WIN32
    WSACleanup();
#endif

    Logger::log("Captive Portal: HTTP server stopped.", Logger::INFO);
}

void CaptivePortal::runServerLoop() {
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        Logger::log("Captive Portal: Failed to create socket.", Logger::ERROR);
        running = false;
        return;
    }

    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(serverPort);

    if (bind(serverSocket, (struct sockaddr*)&address, sizeof(address)) < 0) {
        Logger::log("Captive Portal: Bind failed on port " + std::to_string(serverPort), Logger::ERROR);
        close_socket(serverSocket);
        serverSocket = -1;
        running = false;
        return;
    }

    if (listen(serverSocket, 10) < 0) {
        Logger::log("Captive Portal: Listen failed.", Logger::ERROR);
        close_socket(serverSocket);
        serverSocket = -1;
        running = false;
        return;
    }

    while (running.load()) {
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(serverSocket, &readFds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int selectRet = select(serverSocket + 1, &readFds, nullptr, nullptr, &tv);
        if (selectRet > 0) {
            struct sockaddr_in clientAddr;
#ifdef _WIN32
            int addrLen = sizeof(clientAddr);
#else
            socklen_t addrLen = sizeof(clientAddr);
#endif
            int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrLen);
            
            if (clientSocket >= 0) {
                char ipBuf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &clientAddr.sin_addr, ipBuf, sizeof(ipBuf));
                std::string clientIp = ipBuf;

                std::thread(&CaptivePortal::handleClientConnection, this, clientSocket, clientIp).detach();
            }
        }
    }

    if (serverSocket >= 0) {
        close_socket(serverSocket);
        serverSocket = -1;
    }
}

void CaptivePortal::handleClientConnection(int clientSocket, const std::string& clientIp) {
    char buffer[2048] = {0};
    int bytesRead = read_socket(clientSocket, buffer, sizeof(buffer) - 1);
    if (bytesRead < 0) {
        close_socket(clientSocket);
        return;
    }

    std::string request(buffer);
    std::string response = "";
    bool showLoginError = false;

    // Handle Login authentication POST requests
    if (request.find("POST") != std::string::npos) {
        // Find body parameters: e.g. username=admin&password=admin123
        size_t bodyPos = request.find("\r\n\r\n");
        if (bodyPos != std::string::npos) {
            std::string body = request.substr(bodyPos + 4);
            
            std::string userParam = "username=";
            std::string passParam = "password=";
            
            size_t userIdx = body.find(userParam);
            size_t passIdx = body.find(passParam);
            
            std::string username = "";
            std::string password = "";
            
            if (userIdx != std::string::npos && passIdx != std::string::npos) {
                // Assuming format: username=xxx&password=yyy
                size_t userEnd = body.find('&', userIdx);
                username = body.substr(userIdx + userParam.size(), userEnd - userIdx - userParam.size());
                password = body.substr(passIdx + passParam.size());
                
                // Decode HTTP encodings if any (simple decoding for common special characters)
                std::replace(username.begin(), username.end(), '+', ' ');
                std::replace(password.begin(), password.end(), '+', ' ');
            }

            if (authenticateClient(clientIp, username, password)) {
                // Success Response
                response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n";
                response += "<html><head><title>Authentication Successful</title>";
                response += "<style>body{font-family:'Segoe UI',Arial,sans-serif;background-color:#f4f7f6;text-align:center;padding:50px;}";
                response += ".card{background:white;padding:40px;border-radius:10px;box-shadow:0 4px 6px rgba(0,0,0,0.1);max-width:500px;margin:auto;}";
                response += "h1{color:#2ecc71;}p{color:#666;}</style></head>";
                response += "<body><div class='card'><h1>YUNA Firewall - Login Successful!</h1>";
                response += "<p>Your device IP <b>" + clientIp + "</b> has been whitelisted. You now have unrestricted WAN/Internet access.</p>";
                response += "<br><a href='http://google.com' style='color:#3498db;text-decoration:none;font-weight:bold;'>Proceed to Web</a></div></body></html>";
                send(clientSocket, response.c_str(), response.size(), 0);
                close_socket(clientSocket);
                return;
            } else {
                showLoginError = true;
            }
        }
    }

    // Serve HTML Login Page
    std::string htmlBody = "<html><head><title>YUNA Firewall Gateway</title>";
    htmlBody += "<style>";
    htmlBody += "body { font-family:'Segoe UI',Arial,sans-serif; background: linear-gradient(135deg, #1f4068, #162447); display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }";
    htmlBody += ".login-card { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.3); width: 100%; max-width: 400px; text-align: center; }";
    htmlBody += "h2 { color: #1f4068; margin-bottom: 5px; }";
    htmlBody += "p.subtitle { color: #888; font-size: 13px; margin-bottom: 25px; }";
    htmlBody += ".form-group { margin-bottom: 20px; text-align: left; }";
    htmlBody += "label { display: block; font-size: 12px; color: #555; font-weight: bold; margin-bottom: 5px; }";
    htmlBody += "input[type='text'], input[type='password'] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }";
    htmlBody += "input[type='submit'] { background-color: #e43f5a; color: white; border: none; padding: 12px; width: 100%; border-radius: 4px; font-weight: bold; cursor: pointer; transition: background 0.3s; }";
    htmlBody += "input[type='submit']:hover { background-color: #ca3e52; }";
    htmlBody += ".error-box { background-color: #ffe6e6; border: 1px solid #ff9999; color: #cc0000; padding: 10px; border-radius: 4px; margin-bottom: 20px; font-size: 13px; }";
    htmlBody += "</style></head><body>";
    htmlBody += "<div class='login-card'><h2>YUNA Authentication Gateway</h2>";
    htmlBody += "<p class='subtitle'>Please log in to authorize internet access for IP: <b>" + clientIp + "</b></p>";
    
    if (showLoginError) {
        htmlBody += "<div class='error-box'>Authentication failed. Please verify your credentials.</div>";
    }

    htmlBody += "<form method='POST'><div class='form-group'><label>Username</label><input type='text' name='username' required></div>";
    htmlBody += "<div class='form-group'><label>Password</label><input type='password' name='password' required></div>";
    htmlBody += "<input type='submit' value='Authenticate Device'></form></div></body></html>";

    response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + std::to_string(htmlBody.size()) + "\r\nConnection: close\r\n\r\n" + htmlBody;
    send(clientSocket, response.c_str(), response.size(), 0);
    close_socket(clientSocket);
}

bool CaptivePortal::authenticateClient(const std::string& ip, const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(portalMutex);
    
    // Check credentials matching
    bool ok = false;
    for (const auto& u : users) {
        if (u.username == username && u.password == password) {
            ok = true;
            break;
        }
    }

    if (ok) {
        // Revoke existing session for the IP if any
        sessions.erase(std::remove_if(sessions.begin(), sessions.end(), [&ip](const ActiveSession& s) {
            return s.ip == ip;
        }), sessions.end());

        // Create new active session
        ActiveSession session;
        session.ip = ip;
        session.username = username;
        session.loginTime = getCurrentTimestamp();
        session.bytesTransferred = 0;
        sessions.push_back(session);

        // Add firewall rule bypass dynamically on whitelisting
        // Allow source address to reach anywhere
        std::string cmd = "firewall-cmd --permanent --remove-rich-rule='rule family=\"ipv4\" source address=\"" + ip + "\" drop'";
        manager->blockIPAddress(ip); // Dummy run/clean
        // We bypass by removing it from FirewallManager blockedIPs
        manager->unblockIPAddress(ip);

        Logger::log("Captive Portal: Client IP " + ip + " successfully authenticated as user " + username, Logger::WARNING);
        return true;
    }
    return false;
}

void CaptivePortal::revokeClient(const std::string& ip) {
    std::lock_guard<std::mutex> lock(portalMutex);
    auto it = std::remove_if(sessions.begin(), sessions.end(), [&ip](const ActiveSession& s) {
        return s.ip == ip;
    });
    if (it != sessions.end()) {
        sessions.erase(it, sessions.end());
        
        // Re-enforce blocking rule
        manager->blockIPAddress(ip);
        Logger::log("Captive Portal: Revoked authentication session for IP: " + ip, Logger::INFO);
    }
}

bool CaptivePortal::isClientAuthenticated(const std::string& ip) {
    // Localhost loopback is always authenticated
    if (ip == "127.0.0.1" || ip == "localhost" || ip == "::1") return true;

    std::lock_guard<std::mutex> lock(portalMutex);
    for (const auto& s : sessions) {
        if (s.ip == ip) return true;
    }
    return false;
}

bool CaptivePortal::addUser(const std::string& username, const std::string& password) {
    if (username.empty() || password.empty()) return false;
    std::lock_guard<std::mutex> lock(portalMutex);
    
    // Check duplication
    for (const auto& u : users) {
        if (u.username == username) return false;
    }

    PortalUser user;
    user.username = username;
    user.password = password;
    user.role = "user";
    
    users.push_back(user);
    saveUsers();
    
    Logger::log("Captive Portal: Added portal login user: " + username, Logger::INFO);
    return true;
}

bool CaptivePortal::removeUser(const std::string& username) {
    if (username == "admin") return false; // Prevent admin lockout
    std::lock_guard<std::mutex> lock(portalMutex);
    
    auto it = std::remove_if(users.begin(), users.end(), [&username](const PortalUser& u) {
        return u.username == username;
    });
    
    if (it != users.end()) {
        users.erase(it, users.end());
        saveUsers();
        Logger::log("Captive Portal: Removed portal user: " + username, Logger::INFO);
        return true;
    }
    return false;
}

std::vector<PortalUser> CaptivePortal::getUsers() {
    std::lock_guard<std::mutex> lock(portalMutex);
    return users;
}

std::vector<ActiveSession> CaptivePortal::getSessions() {
    std::lock_guard<std::mutex> lock(portalMutex);
    return sessions;
}
