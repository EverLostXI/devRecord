#include <iostream>
#include <string>
#include <cstring>
#include <map>
// 获取时间戳
#include <ctime>
// Windows提供的socket API
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
// 生成服务器日志
#include <fstream>
#include <iomanip>
// C++ 11线程库
#include <thread>
// 链接WinSock库
// #pragma comment(lib, "ws2_32.lib") 非MSVC编译器无法识别，必须手动链接Winsock库
// 服务端已经用CMake链接


using namespace std;


// 设置服务器端口号
const int PORT = 8888;
// 设置listen连接队列长度
const int BACKLOG = 5;

// 获取时间戳
string TimeStamp() {
    time_t currentTime = time(nullptr); //不是可直接阅读的日历时间
    tm* localTime = localtime(&currentTime); //转换为服务器本地时间
    stringstream ss; // 开始生成时间戳
    ss << "[" << put_time(localTime, "%Y-%m-%d %H:%M:%S") << "]";
    return ss.str();
}


// 初始化服务器日志
ofstream logFile; // 初始化文件句柄

string FileNameGen() { // 将日志以当前日期命名,逻辑与获取时间戳函数一致
    time_t currentTime = time(nullptr);
    tm* localTime = localtime(&currentTime);
    stringstream fname;
    fname << put_time(localTime, "%Y%m%d");
    fname << ".log";
    return fname.str();
}

// 日志写入函数
enum class LogLevel { // 限定日志级别
    FATAL_LEVEL, // 系统崩溃或不可恢复的错误
    ERROR_LEVEL, // 运行时错误，功能受影响但程序仍在运行
    WARN_LEVEL, // 潜在的问题或异常情况
    INFO_LEVEL, // 程序正常运行的关键步骤
    DEBUG_LEVEL, // 详细的调试信息
    TRACE_LEVEL // 追踪细致操作
};

string LevelToString(LogLevel level) { // 将日志级别转为字符串
    switch (level) {
        case LogLevel::FATAL_LEVEL: return "FATAL";
        case LogLevel::ERROR_LEVEL: return "ERROR";
        case LogLevel::WARN_LEVEL: return "WARN";
        case LogLevel::INFO_LEVEL: return "INFO";
        case LogLevel::DEBUG_LEVEL: return "DEBUG";
        case LogLevel::TRACE_LEVEL: return "TRACE";
        default: return "UNKNOWN";
    }
}

void WriteLog(LogLevel level, const string& message) { //包含两个参数：重要级，消息内容
    if (logFile.is_open()) {
        logFile << TimeStamp() << "[" << LevelToString(level) << "]" << message << endl;
        logFile.flush(); //立即刷新缓冲区
    }
}

void InitializeLogFile() { // 生成文件
    const string LOG_FOLDER = "log/";
    string logfilename = LOG_FOLDER + FileNameGen();
    logFile.open(logfilename, ios::out | ios::app);
    if (!logFile.is_open()) {
        cerr << "无法打开日志文件：" << logfilename << endl; // 此时无法写入日志，因为日志都没打开
    } else {
        string message = "日志文件初始化成功：" + logfilename;
        WriteLog(LogLevel::INFO_LEVEL, message);
    }
}

void CloseLogFile() {
    if (logFile.is_open()) {
        WriteLog(LogLevel::INFO_LEVEL, "关闭日志文件");
        logFile.close();
    }
}


// 初始化和清理Winsock
bool InitializeWinSock() {
    WSADATA wsadata;
    if (WSAStartup(MAKEWORD(2,2), &wsadata) !=0) {
        string errormessage = "WSA启动失败:" + to_string(WSAGetLastError());
        WriteLog(LogLevel::FATAL_LEVEL, errormessage);
        return false;
    }
    WriteLog(LogLevel::DEBUG_LEVEL, "WinSock 2.2 初始化成功");
    return true;
}

void CleanupWinSock() {
    WSACleanup();
    WriteLog(LogLevel::DEBUG_LEVEL, "WinSock 清理完成");
}


// 配置服务器地址
int SetupServerAddress(const int port, sockaddr_in& address_info) {
    if (port <= 0 || port > 65535) {
        WriteLog(LogLevel::FATAL_LEVEL, "配置的端口号无效");
        return -1;
    }
    memset(&address_info, 0, sizeof(address_info)); // 清零结构体
    address_info.sin_family = AF_INET; // 设置地址族为IPv4
    address_info.sin_addr.s_addr = htonl(INADDR_ANY); //设置IP地址：监听所有接口（转换为网络字节序）
    address_info.sin_port = htons(port); // 设置端口号（转换为网络字节序）
    return 0;
}



// 存储账号密码
map<string, string> g_userCredentials = {

};

// 用户类
class ClientSession {
public:
    // 网络属性
    SOCKET socket_fd;
    string client_ip;
    unsigned short client_port;
    // 认证状态
    string username;
    bool is_authenticated;
    // 最后收到心跳时间
    time_t last_heartbeat_time;

public:
    // 构造函数：初始化用户属性
    ClientSession(SOCKET fd, const string& ip, unsigned short port)
        : socket_fd(fd), 
        client_ip(ip), 
        client_port(port), 
        username(""), // 初始为空
        is_authenticated(false), // 初始未认证
        last_heartbeat_time(time(NULL)) // 初始化为当前时间
    { // 向日志中记录用户登录
        string logmessage = "用户登录: IP = " + client_ip + "端口 = " + to_string(client_port);
        WriteLog(LogLevel::INFO_LEVEL, logmessage);
    }
    // 认证方法
    void authenticate(const string& user) {
        this->username = user;
        this->is_authenticated = true;
    }

    // 更新心跳方法
    void updateHeartbeat() {
        last_heartbeat_time = time(NULL);
    }
};

// 创建账户：要求用户输入账号和密码，将账号密码作为键值对存入g_userCredentials，再创建一个用户类并认证
// 账户登录：用户输出账号密码，比对g_userCredentials中的键值对，如果成功，将会话状态标记为已认证，后续服务器通过检查会话状态来判断该客户端是否有权发送消息


// 验证登录凭证函数
bool AuthenticateCredential(const string &inputUsername, const string &inputPassword) {
    if (g_userCredentials.count(inputUsername)) { // 检查map中是否存有该用户名
        if (g_userCredentials[inputUsername] == inputPassword) { // 如果存在，比较密码
            return true;
        }
    }
    return false;
}

/* 用户端发送消息函数 
协议字节格式：
1.头部
    消息总长度
    消息类型
    回复目标ID（为0表示不是回复）
    服务器时间戳（客户端发送时为0）
2. 消息体结构（变长）
    @列表长度
    @的用户列表
    消息本体长度
    消息本体

客户端普通消息封装函数
void CommonMessage() {

}

*/


// 工作线程入口函数
void HandleClient(ClientSession* sessionPtr) {
    // 线程启动后，所有操作都使用 sessionPtr->socket_fd 来进行通信

}


int main() {
    // 初始化日志文件
    InitializeLogFile();

    // 初始化WinSock
    if (!InitializeWinSock()) {
        CloseLogFile();
        return 1;
    }

    // 创建Socket
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        string errormessage = "Socket 创建失败:" + to_string(WSAGetLastError());
        WriteLog(LogLevel::FATAL_LEVEL, errormessage);
        CleanupWinSock();
        CloseLogFile();
        return 1;
    }
    WriteLog(LogLevel::INFO_LEVEL, "Socket 创建成功");

    // 调用配置地址函数
    sockaddr_in service_address;
    int iResult;
    if (SetupServerAddress(PORT, service_address) != 0) {
        WriteLog(LogLevel::FATAL_LEVEL, "服务器地址配置失败");
        closesocket(listenSocket);
        CleanupWinsock();
        CloseLogFile();
        return 1;
    }
    WriteLog(LogLevel::INFO_LEVEL, "服务器地址配置成功");

    // 执行bind
    iResult = bind(listenSocket, (SOCKADDR*)&service_address, sizeof(service_address));

    if (iResult == SOCKET_ERROR) {
        string errormessage = "Bind失败: " + to_string(WSAGetLastError());
        WriteLog(LogLevel::FATAL_LEVEL, errormessage);
        closesocket(listenSocket);
        CleaupWinSock();
        CloseLogFile();
        return 1;
    }
    WriteLog(LogLevel::INFO_LEVEL, "Socket 成功绑定到端口 " + std::to_string(LISTEN_PORT));

    // 执行listen
    iResult = listen(listenSocket, BACKLOG);
    if(iResult == SOCKET_ERROR) {
        string errormessage = "Listen 失败: " + to_string(WSAGetLastError());
        WriteLog(LogLevel::FATAL_LEVEL, erroemessage);
        closesocket(listenSocket);
        CleanupWinSock();
        CloseLogFile();
        return 1;
    }
    WriteLog(LogLevel::INFO_LEVEL, "服务器开始监听连接...")



}