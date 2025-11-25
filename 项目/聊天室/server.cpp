#include <iostream>
#include <string>
#include <cstring>
#include <map>
#include <vector>
#include <sstring>
// 获取时间戳
#include <ctime>
// 网络连接部分
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <cstdint>
// 生成服务器日志
#include <fstream>
#include <iomanip>
// 线程库
#include <thread>
// 需要链接WinSock库
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
    { // 向日志中记录用户登录
        string logmessage = "用户登录: IP = " + client_ip + "端口 = " + to_string(client_port);
        WriteLog(LogLevel::INFO_LEVEL, logmessage);
    }
    // 认证方法
    void authenticate(const string& user) {
        this->username = user;
        this->is_authenticated = true;
    }

};

// 创建账户：要求用户输入账号和密码，将账号密码作为键值对存入g_userCredentials，再创建一个用户类并认证
/* 账户登录：用户输出账号密码，比对g_userCredentials中的键值对，如果成功，将会话状态标记为已认证，
后续服务器通过检查会话状态来判断该客户端是否有权发送消息*/
// 然后将输入的账号与新创建的用户对象绑定，这样其他人发消息过来的时候可以使用id指明接收人

/*注意：现在一旦服务器关停，所有的账户信息都会被抹除，如果想要永久记录，除非手
动输入，否则可能需要通过构建数据库例如使用SQLite，然而这样工作量就太大了，因此
目前只能先这样了。当然也可以通过读取文件的方式在重启服务器的时候重新创建，然而
那样并不是一个很好的解决方案，如果用户量增多，重新创建用户对象的时间会难以估量
*/

// 存储ID与密码 （可以在客户端部署对密码的不可逆加密）
map<uint32_t, string> g_userCredentials = {

};

//将ID与用户对象对应
map<uint32_t, ClientSession> g_userSessions = {

}



// 工作线程入口函数(未完成)
void HandleClient(ClientSession* sessionPtr) { // 这个会话指针作为一个客户端在内存中的唯一代表
    // 线程启动后，所有操作都使用 sessionPtr->socket_fd 来进行通信
    
    // 发送消息通知用户登录
    send();
    //接受登录凭证(接收到前会阻塞)
    int login_received = recv(sessionPtr->socket_fd, );
    // 解析登录凭证并标记会话状态（封装）

    //发送结果给客户端

    // 验证是否认证成功，如果失败，断开连接
    if (!sessionPtr->is_authenticated) {
        string message = "未认证用户连接断开:" + sessionPtr.client_ip;
        WriteLog(LogLevel:INFO_LEVEL, message);
    }
}
// 客户端消息封装函数
/* 目录：
普通消息(common)
登录请求(login)
创建群聊(group)
*/

//定义消息类型
enum MsgType {
    COMMON = 1,
    LOGIN = 2,
    GROUP = 3
};

// 封装写入辅助函数(由于在每个封装函数中被多次调用，使用inline函数加速)
//写入uint32_t
inline void WriteUint32(vector<char>& buffer, size_t& offset, uint32_t value) { // 因为要使用memcpy，所以设置一个offset手动控制数据偏移量
    uint32_t netValue = htonl(value);
    memcpy(&buffer[offset], &netValue, sizeof(netValue)); // 用memcpy进行复制操作
    offset += sizeof(netValue);
}
//写入字符串
inline void WriteString(vector<char>& buffer, size_t& offset, const string& str) {
    WriteUint32(buffer, offset, static_cast<uint32_t>(str.size())); // 把数据长度转换为uint32_t的固定长度（4字节）
    memcpy(&buffer[offset], str.data(), str.size());
    offset += str.size();
}
// 使用重载函数直接在传入参数的时候判断消息类型
vector<char> MsgPackage(const string& content, uint32_t receiverID) { //普通消息，包含消息与接收人
    // 计算包体大小
    // 整条消息的结构为：消息类型（4字节）/后面所有东西的长度/接收者ID（4字节）/内容长度（4字节）/内容体
    uint32_t contentLength = static_cast<uint32_t>(content.size()); // 内容长度
    uint32_t bodyLength = 8 + contentLength;  // 消息体长度 = receiverID + contentLength + 内容体
    size_t totalSize = 8 + bodyLength;  // 消息类型 + 消息体长度
    // 初始化包体
    vector<char> package(totalSize);
    size_t offset = 0;
    // 写入数据
    WriteUint32(package, offset, static_cast<uint32_t>(MsgType::COMMON));
    WriteUint32(package, offset, bodyLength);
    WriteUint32(package, offset, receiverID);
    WriteString(package, offset, content);
    
    return package;
}

vector<char> MsgPackage(uint32_t accountID, const string& password) { // 登录请求，包含账户ID与密码
    // 计算包体大小
    // 整条消息的结构为：消息类型（4字节）/后面所有东西的长度/账户ID（4字节）/密码长度（4字节）/密码
    uint32_t passwordLength = static_cast<uint32_t>(password.size());
    uint32_t bodyLength = 8 + passwordLength; // accountID + passwordLength
    size_t totalSize = 8 + bodyLength; //与普通消息相同，不再赘述
    // 初始化
    vector<char> package(totalSize);
    size_t offset = 0;

    WriteUint32(package, offset, static_cast<uint32_t>(MsgType::LOGIN));
    WriteUint32(package, offset, bodyLength);
    WriteUint32(package, offset, accountID);
    WriteString(package, offset, password);
}

vector<char> MsgPackage(const vector<uint32_t>& memberIDs) { // 创建群聊，包含群聊成员ID（也包含自己）
    // 计算包体大小
    // 整条消息的结构为：消息类型（4字节）/消息体长度（4字节）/成员数量（4字节）/成员ID列表
    uint32_t memberCount = static_cast<uint32_t>(memberIDs.size());
    uint32_t bodyLength = sizeof(memberCount) + memberCount * sizeof(uint32_t);
    size_t totalSize = 8 + bodyLength;  // 消息类型(4) + 消息体长度(4) + 消息体
    
    // 初始化包体
    vector<char> package(totalSize);
    size_t offset = 0;
    
    // 写入数据
    WriteUint32(package, offset, static_cast<uint32_t>(MsgType::GROUP));
    WriteUint32(package, offset, bodyLength);
    WriteUint32(package, offset, memberCount);
    
    // 写入每个成员的ID
    for (uint32_t memberID : memberIDs) {
        WriteUint32(package, offset, memberID);
    }
    
    return package;
}
// 客户端消息解包函数
/* 目录：
普通消息(common)
登录请求结果(login)
被拉入群聊(group)
*/



// ==================== 服务端消息解包函数 ====================
/* 目录：
普通消息（包含转发）(common)
登录请求（包含发送结果）(login)
创建群聊（包含转发拉入群聊）(group)
*/

// 封装读取辅助函数
// 读取 uint32_t（从网络字节序转为主机字节序）
inline uint32_t ReadUint32(const vector<char>& buffer, size_t& offset) {
    uint32_t netValue;
    memcpy(&netValue, &buffer[offset], sizeof(netValue));
    offset += sizeof(netValue);
    return ntohl(netValue);  // 网络字节序 -> 主机字节序
}

// 读取字符串（先读长度，再读内容）
inline string ReadString(const vector<char>& buffer, size_t& offset) {
    uint32_t length = ReadUint32(buffer, offset);
    string result(length, '\0');
    memcpy(&result[0], &buffer[offset], length);
    offset += length;
    return result;
}

// 消息解包主函数
bool MsgUnpack(const vector<char>& recvBuffer, SOCKET clientSocket) {
    if (recvBuffer.size() < 8) {  // 至少需要消息类型(4) + 消息体长度(4)
        WriteLog(LogLevel::ERROR_LEVEL, "收到的消息过短，无法解析");
        return false;
    }
    
    size_t offset = 0;
    
    // 1. 读取消息类型
    uint32_t msgType = ReadUint32(recvBuffer, offset);
    
    // 2. 读取消息体长度
    uint32_t bodyLength = ReadUint32(recvBuffer, offset);
    
    // 3. 验证消息完整性
    if (recvBuffer.size() != 8 + bodyLength) {
        string errMsg = "消息长度不匹配：期望 " + to_string(8 + bodyLength) + 
                        " 字节，实际 " + to_string(recvBuffer.size()) + " 字节";
        WriteLog(LogLevel::ERROR_LEVEL, errMsg);
        return false;
    }
    
    // 4. 根据消息类型分发处理
    switch (msgType) {
        case MsgType::COMMON: {
            // 普通消息：receiverID(4) + contentLength(4) + content
            uint32_t receiverID = ReadUint32(recvBuffer, offset);
            string content = ReadString(recvBuffer, offset);
            
            // 处理逻辑：转发消息
            HandleCommonMessage(clientSocket, receiverID, content);
            break;
        }
        
        case MsgType::LOGIN: {
            // 登录请求：accountID(4) + passwordLength(4) + password
            uint32_t accountID = ReadUint32(recvBuffer, offset);
            string password = ReadString(recvBuffer, offset);
            
            // 处理逻辑：验证登录
            HandleLoginRequest(clientSocket, accountID, password);
            break;
        }
        
        case MsgType::GROUP: {
            // 创建群聊：memberCount(4) + memberID1(4) + memberID2(4) + ...
            uint32_t memberCount = ReadUint32(recvBuffer, offset);
            vector<uint32_t> memberIDs;
            memberIDs.reserve(memberCount);
            
            for (uint32_t i = 0; i < memberCount; ++i) {
                uint32_t memberID = ReadUint32(recvBuffer, offset);
                memberIDs.push_back(memberID);
            }
            
            // 处理逻辑：创建群聊并通知成员
            HandleGroupCreation(clientSocket, memberIDs);
            break;
        }
        
        default: {
            string errMsg = "未知的消息类型: " + to_string(msgType);
            WriteLog(LogLevel::WARN_LEVEL, errMsg);
            return false;
        }
    }
    
    return true;
}

// ==================== 消息处理函数 ====================
// 这些是具体的业务逻辑处理函数，需要根据你的需求实现

// 处理普通消息（转发给接收者）
void HandleCommonMessage(SOCKET senderSocket, uint32_t receiverID, const string& content) {
    string logMsg = "收到普通消息，接收者ID: " + to_string(receiverID) + 
                    ", 内容: " + content;
    WriteLog(LogLevel::INFO_LEVEL, logMsg);
    
    // TODO: 查找接收者的 socket，转发消息
    // if (g_userSessions.count(receiverID)) {
    //     SOCKET receiverSocket = g_userSessions[receiverID].socket_fd;
    //     vector<char> forwardMsg = MsgPackage(content, receiverID);
    //     send(receiverSocket, forwardMsg.data(), forwardMsg.size(), 0);
    // }
}

// 处理登录请求（验证并发送结果）
void HandleLoginRequest(SOCKET clientSocket, uint32_t accountID, const string& password) {
    string logMsg = "收到登录请求，账户ID: " + to_string(accountID);
    WriteLog(LogLevel::INFO_LEVEL, logMsg);
    
    // TODO: 验证账户密码
    // bool authSuccess = (g_userCredentials.count(accountID) && 
    //                     g_userCredentials[accountID] == password);
    // 
    // if (authSuccess) {
    //     // 标记会话为已认证
    //     // 发送登录成功消息
    // } else {
    //     // 发送登录失败消息
    // }
}

// 处理群聊创建（通知所有成员）
void HandleGroupCreation(SOCKET creatorSocket, const vector<uint32_t>& memberIDs) {
    string logMsg = "收到创建群聊请求，成员数: " + to_string(memberIDs.size());
    WriteLog(LogLevel::INFO_LEVEL, logMsg);
    
    // TODO: 创建群聊，并通知所有成员
    // for (uint32_t memberID : memberIDs) {
    //     if (g_userSessions.count(memberID)) {
    //         // 发送加入群聊通知
    //     }
    // }
}

// 验证登录凭证函数
bool AuthenticateCredential(const string &inputUsername, const string &inputPassword) {
    if (g_userCredentials.count(inputUsername)) { // 检查map中是否存有该用户名
        if (g_userCredentials[inputUsername] == inputPassword) { // 如果存在，比较密码
            return true;
        }
    }
    return false;
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

    if (iResult == SOCKET_ERROR) { // 错误处理
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

    if(iResult == SOCKET_ERROR) { // 错误处理
        string errormessage = "Listen 失败: " + to_string(WSAGetLastError());
        WriteLog(LogLevel::FATAL_LEVEL, erroemessage);
        closesocket(listenSocket);
        CleanupWinSock();
        CloseLogFile();
        return 1;
    }
    WriteLog(LogLevel::INFO_LEVEL, "服务器开始监听连接...")



}