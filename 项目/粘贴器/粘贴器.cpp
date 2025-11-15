#include <iostream>
#include <fstream>
#include <windows.h>
#include <string>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <filesystem>
std::vector<std::wstring> ReadandSplit(const std::string& filename) {
    std::wifstream file(filename);
    if (!file) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return {};
    }

    std::wstringstream buffer;
    buffer << file.rdbuf();
    std::wstring content = buffer.str();
    std::vector<std::wstring> sentences;
    std::wstringstream content_stream(content);
    std::wstring line;

    while (std::getline(content_stream, line)) {
        if (!line.empty() && line.back() == L'\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            sentences.push_back(line);
        }
        return sentences;
    }
}
bool setClipboardText(const std::wstring& text) {
    if (!OpenClipboard(NULL)) {
        return false;
    }

    struct ClipboardCloser { ~ClipboardCloser() { CloseClipboard(); } } closer; 

    EmptyClipboard();

    const size_t size = (text.size() + 1) * sizeof(wchar_t); 
    HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, size);
    if (hGlobal == NULL) { return false; }

    LPWSTR lpData = (LPWSTR)GlobalLock(hGlobal); 
    if (lpData == NULL) { 
        GlobalFree(hGlobal);
        return false; 
    }

    memcpy(lpData, text.c_str(), size);

    GlobalUnlock(hGlobal); 

    if (SetClipboardData(CF_UNICODETEXT, hGlobal) == NULL) {
        GlobalFree(hGlobal);
        return false;
    }
    return true;
}

void simulateKey(WORD vKey) {
    INPUT ip;
    ip.type = INPUT_KEYBOARD;
    ip.ki.wScan = 0;
    ip.ki.time = 0;
    ip.ki.dwExtraInfo = 0;

    ip.ki.wVk = vKey;
    ip.ki.dwFlags = 0;
    SendInput(1, &ip, sizeof(INPUT));

    ip.ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(1, &ip, sizeof(INPUT));
}

void simulateCombinationKey(WORD vKey1, WORD vKey2) {
    INPUT inputs[4] = {};
    inputs[0].type = INPUT_KEYBOARD;
    inputs[0].ki.wScan = 0;
    inputs[0].ki.time = 0;
    inputs[0].ki.dwExtraInfo = 0;

    inputs[0].ki.wVk = vKey1;
    inputs[0].ki.dwFlags = 0;

    inputs[1].type = INPUT_KEYBOARD;
    inputs[1].ki.wScan = 0;
    inputs[1].ki.time = 0;
    inputs[1].ki.dwExtraInfo = 0;
    inputs[1].ki.wVk = vKey2;
    inputs[1].ki.dwFlags = 0;

    inputs[2].type = INPUT_KEYBOARD;
    inputs[2].ki.wScan = 0;
    inputs[2].ki.time = 0;
    inputs[2].ki.dwExtraInfo = 0;
    inputs[2].ki.wVk = vKey2;
    inputs[2].ki.dwFlags = KEYEVENTF_KEYUP;

    inputs[3].type = INPUT_KEYBOARD;
    inputs[3].ki.wScan = 0;
    inputs[3].ki.time = 0;
    inputs[3].ki.dwExtraInfo = 0;
    inputs[3].ki.wVk = vKey1;
    inputs[3].ki.dwFlags = KEYEVENTF_KEYUP;

    SendInput(4, inputs, sizeof(INPUT));
}

void autoPasteAndEnter(int delay_ms_v = 50,int delay_ms_e = 50) {
    simulateCombinationKey(VK_CONTROL, 'V');
    Sleep(delay_ms_v); 

    simulateKey(VK_RETURN);
    Sleep(delay_ms_e); 
}
void sendSentencesSequentially(const std::vector<std::wstring>& sentences) {
    if (sentences.empty()) {
        std::wcout << L"句子列表为空，无需操作。\n";
        return;
    }
    
    std::wcout << L"--- 请在 5 秒内将光标切换到目标输入框 --- \n";
    // 初始等待时间，让用户有时间切换窗口
    Sleep(5000); 

    std::wcout << L"--- 开始自动发送句子 ---\n";

    for (size_t i = 0; i < sentences.size(); ++i) {
        const std::wstring& sentence = sentences[i];

        // 1. 复制当前句子到剪切板
        std::wcout << L"[" << (i + 1) << L"/" << sentences.size() << L"] 正在复制并发送： " << sentence << L"\n";
        
        if (!setClipboardText(sentence)) {
            std::wcerr << L"错误：复制第 " << (i + 1) << L" 句时失败，停止操作。\n";
            break; 
        }

        // 2. 模拟粘贴和回车操作
        // 注意：这里的延迟(50ms)可能需要根据目标应用程序的响应速度进行调整。
        autoPasteAndEnter(50, 50);
        
        // 可选：在句子间增加稍微长一点的延迟，以便用户能看清操作或程序处理下一句
        Sleep(300); 
    }
    
    std::wcout << L"--- 所有句子发送完毕。---\n";
}
int main() {
    const std::string filename = "cn.txt";
    std::vector<std::wstring> sentences = ReadandSplit(filename);
    if (sentences.empty()) {
        std::wcerr << L"文件中没有可复制的句子或文件打开失败。\n";
        return 1;
    }
    
    sendSentencesSequentially(sentences);

    std::cin.get();
    return 0;
}