#include <windows.h>
#include <tlhelp32.h>
#include <lmcons.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <conio.h>
#include <map>
#include <functional>
#include <thread>
#include <atomic>
#include <algorithm>
#include <memory>
#include <io.h>
#include <fcntl.h>
#include <mutex>
#include <chrono>

using namespace std;

struct ProcessInfo {
    wstring name;
    DWORD pid = 0;        // 初始化为 0
    HANDLE handle = NULL; // 初始化为 NULL
};

enum ConsoleState { STATE_USER, STATE_PROCESS, STATE_MEMORY };

struct CommandArgs {
    wstring mainCommand;
    wstring subCommand;
    map<wstring, wstring> options;
    wstring value;
};

struct ScanResult {
    uintptr_t address;
    size_t size;
};

class ConsoleApp;
class Command {
public:
    virtual ~Command() {}
    virtual void execute(ConsoleApp& app, const CommandArgs& args) = 0;
    virtual bool validateArgs(const CommandArgs& args, wstring& error) { return true; }
};

static mutex scanMutex;
static ScanResult g_scanResult = { 0, 0 };
static atomic<bool> g_isScanned{ false };

bool ParseSignature(const wstring& signature, vector<uint8_t>& bytes, vector<bool>& mask) {
    wstringstream ss(signature);
    wstring byteStr;

    bytes.clear();
    mask.clear();

    while (ss >> byteStr) {
        if (byteStr == L"??") {
            bytes.push_back(0);
            mask.push_back(false);
        }
        else {
            try {
                uint8_t byte = static_cast<uint8_t>(wcstoul(byteStr.c_str(), nullptr, 16));
                bytes.push_back(byte);
                mask.push_back(true);
            }
            catch (...) {
                return false;
            }
        }
    }
    return !bytes.empty();
}

void AOBScanThread(HANDLE hProcess, uintptr_t startAddress, uintptr_t endAddress,
    const vector<uint8_t>& bytes, const vector<bool>& mask) {
    size_t patternSize = bytes.size();
    uintptr_t address = startAddress;
    const size_t bufferSize = 1024 * 1024;
    vector<uint8_t> buffer(bufferSize);

    while (address < endAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0) {
            address += 4096;
            continue;
        }

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_NOACCESS)) {

            SIZE_T bytesRead;
            SIZE_T regionSize = min(mbi.RegionSize, bufferSize);
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), regionSize, &bytesRead)) {
                for (size_t i = 0; i <= bytesRead - patternSize; i++) {
                    bool found = true;
                    for (size_t j = 0; j < patternSize; j++) {
                        if (mask[j] && buffer[i + j] != bytes[j]) {
                            found = false;
                            break;
                        }
                    }
                    if (found) {
                        lock_guard<mutex> lock(scanMutex);
                        if (g_scanResult.address == 0) {
                            g_scanResult.address = (uintptr_t)mbi.BaseAddress + i;
                            g_scanResult.size = patternSize;
                        }
                        return;
                    }
                }
            }
        }
        address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (address < startAddress) break;
    }
}

class ProcessCommand : public Command {
public:
    bool validateArgs(const CommandArgs& args, wstring& error) override {
        if (args.subCommand.empty()) {
            error = L"缺少子命令（如 -ls, -r, -AOBS）";
            return false;
        }
        if (args.subCommand == L"-r" && !args.options.count(L"-r")) {
            error = L"process -r 需要指定进程标识";
            return false;
        }
        if (args.subCommand == L"-AOBS" && !args.options.count(L"-AOBS")) {
            error = L"process -AOBS 需要指定特征码";
            return false;
        }
        return true;
    }

    void execute(ConsoleApp& app, const CommandArgs& args) override;
};

class GetCommand : public Command {
public:
    bool validateArgs(const CommandArgs& args, wstring& error) override {
        if (args.subCommand != L"-get") {
            error = L"仅支持 -get 子命令";
            return false;
        }
        if (!args.options.count(L"-float") && !args.options.count(L"-int")) {
            error = L"需要指定类型（-float 或 -int）";
            return false;
        }
        return true;
    }

    void execute(ConsoleApp& app, const CommandArgs& args) override;
};

class SetCommand : public Command {
public:
    bool validateArgs(const CommandArgs& args, wstring& error) override {
        if (args.subCommand != L"-set") {
            error = L"仅支持 -set 子命令";
            return false;
        }
        if (args.value.empty()) {
            error = L"需要指定要设置的值";
            return false;
        }
        if (!args.options.count(L"-float") && !args.options.count(L"-int")) {
            error = L"需要指定类型（-float 或 -int）";
            return false;
        }
        return true;
    }

    void execute(ConsoleApp& app, const CommandArgs& args) override;
};

class BackCommand : public Command {
public:
    bool validateArgs(const CommandArgs& args, wstring& error) override {
        if (args.mainCommand == L"address-d" && args.subCommand != L"-d") {
            error = L"仅支持 address -d";
            return false;
        }
        if (args.mainCommand == L"process-d" && args.subCommand != L"-d") {
            error = L"仅支持 process -d";
            return false;
        }
        return true;
    }

    void execute(ConsoleApp& app, const CommandArgs& args) override;
};

class ConsoleApp {
private:
    wstring username;
    ConsoleState state;
    ProcessInfo currentProcess;
    uintptr_t currentMemoryAddr;
    vector<ProcessInfo> processList;
    HANDLE hConsole;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    map<wstring, unique_ptr<Command>> commands;

    wstring getUsername() {
        WCHAR username[UNLEN + 1];
        DWORD len = UNLEN + 1;
        GetUserNameW(username, &len);
        return wstring(username);
    }

    void setCursorPosition(int x, int y) {
        COORD pos = { (SHORT)x, (SHORT)y };
        SetConsoleCursorPosition(hConsole, pos);
    }

    void hideCursor() {
        CONSOLE_CURSOR_INFO cursorInfo;
        GetConsoleCursorInfo(hConsole, &cursorInfo);
        cursorInfo.bVisible = FALSE;
        cursorInfo.dwSize = 1;
        SetConsoleCursorInfo(hConsole, &cursorInfo);
    }

    void refreshInputLine(wstring& input) {
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        setCursorPosition(0, csbi.dwSize.Y - 1);
        wcout << wstring(csbi.dwSize.X, L' ') << L"\r";
        displayPrompt();
        wcout << input;
    }

    void displayPrompt() {
        switch (state) {
        case STATE_USER: wcout << L"@" << username << L": "; break;
        case STATE_PROCESS: wcout << L"@" << currentProcess.name << L" " << dec << currentProcess.pid << L": "; break;
        case STATE_MEMORY: wcout << L"@0x" << hex << uppercase << currentMemoryAddr << L": "; break;
        }
    }

public:
    void listProcesses() {
        processList.clear();
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) {
            wcout << L"无法创建进程快照: " << GetLastError() << endl;
            return;
        }

        PROCESSENTRY32W pe = { sizeof(pe) };
        int index = 1;
        if (Process32FirstW(hSnap, &pe)) {
            do {
                ProcessInfo pi{ pe.szExeFile, pe.th32ProcessID, NULL };
                processList.push_back(pi);
                wcout << dec << index++ << L". " << pe.szExeFile << L" " << dec << pe.th32ProcessID << endl;
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    bool openProcess(wstring input) {
        if (currentProcess.handle) CloseHandle(currentProcess.handle);
        currentProcess.handle = NULL;

        DWORD pid = 0;
        if (input.empty()) {
            wcout << L"请提供进程标识" << endl;
            return false;
        }
        if (iswdigit(input[0])) {
            int id = _wtoi(input.c_str()) - 1;
            if (id >= 0 && id < processList.size()) {
                pid = processList[id].pid;
                currentProcess = processList[id];
            }
            else {
                wcout << L"无效的list_id" << endl;
                return false;
            }
        }
        else {
            vector<ProcessInfo> matches;
            for (const auto& proc : processList) {
                wstring name = proc.name;
                if (_wcsicmp(name.c_str(), input.c_str()) == 0 ||
                    _wcsicmp(name.c_str(), (input + L".exe").c_str()) == 0) {
                    matches.push_back(proc);
                }
            }
            if (matches.size() == 1) {
                currentProcess = matches[0];
                pid = matches[0].pid;
            }
            else if (matches.size() > 1) {
                wcout << L"发现多个同名进程，请使用list_id选择：" << endl;
                for (size_t i = 0; i < matches.size(); i++) {
                    wcout << dec << (i + 1) << L". " << matches[i].name << L" " << dec << matches[i].pid << endl;
                }
                return false;
            }
            else {
                wcout << L"未找到匹配的进程" << endl;
                return false;
            }
        }

        if (pid) {
            currentProcess.handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (currentProcess.handle) {
                state = STATE_PROCESS;
                return true;
            }
            else {
                wcout << L"无法打开进程: " << GetLastError() << endl;
            }
        }
        return false;
    }

    vector<uintptr_t> scanAOBS(const wstring& signature) {
        vector<uintptr_t> results;
        auto start = chrono::high_resolution_clock::now();

        vector<uint8_t> bytes;
        vector<bool> mask;
        if (!ParseSignature(signature, bytes, mask)) {
            wcout << L"无效的特征码格式！" << endl;
            state = STATE_PROCESS;
            return results;
        }

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        uintptr_t minAddress = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
        uintptr_t maxAddress = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

        unsigned int threadCount = thread::hardware_concurrency();
        if (threadCount == 0) threadCount = 4;
        vector<thread> threads;

        g_scanResult = { 0, 0 }; // 重置全局扫描结果
        g_isScanned = false;

        uintptr_t rangeSize = (maxAddress - minAddress) / threadCount;
        for (unsigned int i = 0; i < threadCount; ++i) {
            uintptr_t threadStart = minAddress + i * rangeSize;
            uintptr_t threadEnd = (i == threadCount - 1) ? maxAddress : threadStart + rangeSize;
            threads.emplace_back(AOBScanThread, currentProcess.handle, threadStart, threadEnd, ref(bytes), ref(mask));
        }

        for (auto& t : threads) {
            t.join();
        }

        auto end = chrono::high_resolution_clock::now();
        auto durationMs = chrono::duration_cast<chrono::milliseconds>(end - start).count();
        double durationSec = durationMs / 1000.0;
        wcout << L"扫描耗时: " << durationSec << L" 秒" << endl;

        if (g_scanResult.address) {
            results.push_back(g_scanResult.address);
            g_isScanned = true;
        }
        else {
            wcout << L"未找到匹配的地址" << endl;
            state = STATE_PROCESS;
        }

        return results;
    }

    ConsoleApp() : state(STATE_USER), currentMemoryAddr(0), hConsole(GetStdHandle(STD_OUTPUT_HANDLE)) {
        username = getUsername();
        currentProcess.handle = NULL;
        SetConsoleTitleW(L"Linux-Style Memory Tool");
        hideCursor();

        commands[L"process"] = make_unique<ProcessCommand>();
        commands[L"address-get"] = make_unique<GetCommand>();
        commands[L"address-set"] = make_unique<SetCommand>();
        commands[L"address-d"] = make_unique<BackCommand>();
        commands[L"process-d"] = make_unique<BackCommand>();
    }

    ~ConsoleApp() {
        if (currentProcess.handle) CloseHandle(currentProcess.handle);
    }

    void run() {
        wstring input;
        while (true) {
            refreshInputLine(input);

            if (_kbhit()) {
                char ch = _getch();
                if (ch == '\r') {
                    wcout << endl;
                    processCommand(input);
                    input.clear();
                }
                else if (ch == '\b' && !input.empty()) {
                    input.pop_back();
                }
                else if (ch >= 32 && ch <= 126) {
                    input += (wchar_t)ch;
                }
            }

            if (state != STATE_USER && currentProcess.handle) {
                DWORD exitCode;
                if (GetExitCodeProcess(currentProcess.handle, &exitCode) && exitCode != STILL_ACTIVE) {
                    wcout << L"进程已终止，返回初始状态" << endl;
                    CloseHandle(currentProcess.handle);
                    currentProcess.handle = NULL;
                    state = STATE_USER;
                }
            }
            Sleep(50);
        }
    }

    void processCommand(wstring input) {
        input.erase(0, input.find_first_not_of(L" \t"));
        input.erase(input.find_last_not_of(L" \t") + 1);
        if (input.empty()) {
            return;
        }

        wstringstream ss(input);
        CommandArgs args;
        wstring token;

        ss >> args.mainCommand;
        if (args.mainCommand.empty()) {
            wcout << L"命令不能为空" << endl;
            return;
        }

        if (args.mainCommand == L"address") {
            wstring subCmd;
            if (ss >> subCmd) {
                args.mainCommand = L"address" + subCmd;
                args.subCommand = subCmd;
            }
            else {
                wcout << L"缺少子命令（-set, -get 或 -d）" << endl;
                return;
            }
        }
        else if (args.mainCommand == L"process") {
            wstring subCmd;
            if (ss >> subCmd) {
                args.subCommand = subCmd;
                if (subCmd == L"-d") {
                    args.mainCommand = L"process-d"; // 转换为 process-d
                }
                else if (subCmd == L"-r") {
                    ss >> token;
                    if (!token.empty()) {
                        args.options[L"-r"] = token;
                    }
                }
                else if (subCmd == L"-AOBS") {
                    wstring remaining;
                    getline(ss, remaining);
                    remaining.erase(0, remaining.find_first_not_of(L" \t"));
                    if (!remaining.empty()) {
                        if (remaining[0] == L'"') {
                            size_t start = remaining.find(L'"');
                            size_t end = remaining.find(L'"', start + 1);
                            if (end != wstring::npos) {
                                args.options[L"-AOBS"] = remaining.substr(start + 1, end - start - 1);
                            }
                            else {
                                wcout << L"无效的 AOBS 格式，缺少结束引号" << endl;
                                return;
                            }
                        }
                        else {
                            args.options[L"-AOBS"] = remaining;
                        }
                    }
                }
            }
            else {
                wcout << L"缺少子命令（如 -ls, -r, -AOBS, -d）" << endl;
                return;
            }
        }

        auto it = commands.find(args.mainCommand);
        if (it == commands.end()) {
            wcout << L"未知命令: " << args.mainCommand << endl;
            return;
        }
        Command* cmd = it->second.get();

        if (args.mainCommand == L"address-get" || args.mainCommand == L"address-set") {
            wstring type, value;
            if (ss >> type) {
                if (type == L"-float" || type == L"-int") {
                    args.options[type] = L"";
                    if (args.subCommand == L"-set") {
                        if (ss >> value) {
                            args.value = value;
                        }
                        else {
                            wcout << L"缺少设置的值" << endl;
                            return;
                        }
                    }
                }
                else {
                    wcout << L"类型必须为 -float 或 -int" << endl;
                    return;
                }
            }
            else {
                wcout << L"缺少类型（-float 或 -int）" << endl;
                return;
            }
        }

        wstring error;
        if (!cmd->validateArgs(args, error)) {
            wcout << L"命令格式错误: " << error << endl;
            return;
        }

        cmd->execute(*this, args);
    }

    ConsoleState getState() const { return state; }
    void setState(ConsoleState s) { state = s; }
    ProcessInfo& getCurrentProcess() { return currentProcess; }
    uintptr_t& getCurrentMemoryAddr() { return currentMemoryAddr; }
};

void ProcessCommand::execute(ConsoleApp& app, const CommandArgs& args) {
    if (args.subCommand == L"-ls") {
        app.listProcesses();
    }
    else if (args.subCommand == L"-r" && app.getState() == STATE_USER) {
        app.openProcess(args.options.at(L"-r"));
    }
    else if (args.subCommand == L"-AOBS" && app.getState() == STATE_PROCESS) {
        wstring sig = args.options.at(L"-AOBS");
        auto addresses = app.scanAOBS(sig);
        if (!addresses.empty()) {
            if (addresses.size() == 1) {
                app.getCurrentMemoryAddr() = addresses[0];
                app.setState(STATE_MEMORY);
                wcout << L"自动选择唯一地址: 0x" << hex << addresses[0] << endl;
            }
            else {
                for (size_t i = 0; i < addresses.size(); i++) {
                    wcout << dec << (i + 1) << L". 0x" << hex << addresses[i] << endl;
                }
                wcout << L"请选择地址序号: ";
            }
        }
    }
    else {
        wcout << L"当前状态不支持此命令" << endl;
    }
}

void GetCommand::execute(ConsoleApp& app, const CommandArgs& args) {
    if (app.getState() != STATE_MEMORY) {
        wcout << L"请先使用 process -AOBS 选择内存地址" << endl;
        return;
    }

    HANDLE handle = app.getCurrentProcess().handle;
    uintptr_t addr = app.getCurrentMemoryAddr();

    SIZE_T bytesRead;
    if (args.options.count(L"-float")) {
        float value;
        if (ReadProcessMemory(handle, (LPCVOID)addr, &value, sizeof(float), &bytesRead)) {
            wcout << L"Value: " << value << endl;
        }
        else {
            wcout << L"读取失败: " << GetLastError() << endl;
        }
    }
    else if (args.options.count(L"-int")) {
        int value;
        if (ReadProcessMemory(handle, (LPCVOID)addr, &value, sizeof(int), &bytesRead)) {
            wcout << L"Value: " << value << endl;
        }
        else {
            wcout << L"读取失败: " << GetLastError() << endl;
        }
    }
}

void SetCommand::execute(ConsoleApp& app, const CommandArgs& args) {
    if (app.getState() != STATE_MEMORY) {
        wcout << L"请先使用 process -AOBS 选择内存地址" << endl;
        return;
    }

    HANDLE handle = app.getCurrentProcess().handle;
    uintptr_t addr = app.getCurrentMemoryAddr();

    SIZE_T bytesWritten;
    if (args.options.count(L"-float")) {
        try {
            float value = stof(args.value);
            if (WriteProcessMemory(handle, (LPVOID)addr, &value, sizeof(float), &bytesWritten)) {
                wcout << L"设置成功: " << value << endl;
            }
            else {
                wcout << L"设置失败: " << GetLastError() << endl;
            }
        }
        catch (...) {
            wcout << L"无效的浮点数值" << endl;
        }
    }
    else if (args.options.count(L"-int")) {
        try {
            int value = _wtoi(args.value.c_str());
            if (WriteProcessMemory(handle, (LPVOID)addr, &value, sizeof(int), &bytesWritten)) {
                wcout << L"设置成功: " << value << endl;
            }
            else {
                wcout << L"设置失败: " << GetLastError() << endl;
            }
        }
        catch (...) {
            wcout << L"无效的整数值" << endl;
        }
    }
}

void BackCommand::execute(ConsoleApp& app, const CommandArgs& args) {
    if (args.mainCommand == L"address-d" && app.getState() == STATE_MEMORY) {
        app.setState(STATE_PROCESS);
    }
    else if (args.mainCommand == L"process-d" && app.getState() == STATE_PROCESS) {
        app.setState(STATE_USER);
        if (app.getCurrentProcess().handle) {
            CloseHandle(app.getCurrentProcess().handle);
            app.getCurrentProcess().handle = NULL;
        }
    }
    else {
        wcout << L"当前状态不支持此命令" << endl;
    }
}

int main() {
    if (_setmode(_fileno(stdout), _O_U16TEXT) == -1) {
        cerr << "无法设置 Unicode 输出模式" << endl;
        return 1;
    }
    ConsoleApp app;
    app.run();
    return 0;
}