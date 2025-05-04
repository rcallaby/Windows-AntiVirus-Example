#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

#include "memory_scanner.h"
#include "heuristics.h"

void scan_process_memory(HANDLE hProcess, DWORD pid) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    LPCVOID addr = si.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;

    while ((ULONG_PTR)addr < (ULONG_PTR)si.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if ((mbi.State == MEM_COMMIT) &&
                (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ))) {

                BYTE* buffer = (BYTE*)malloc(mbi.RegionSize);
                SIZE_T bytesRead;

                if (ReadProcessMemory(hProcess, addr, buffer, mbi.RegionSize, &bytesRead)) {
                    double entropy = calculate_entropy(buffer, bytesRead);
                    int shellcode_like = detect_shellcode_patterns(buffer, bytesRead);

                    if (entropy > 7.0 || shellcode_like) {
                        printf("  [!] Suspicious region in PID %u at %p | Entropy: %.2f\n", pid, addr, entropy);

                        char filename[64];
                        sprintf(filename, "pid_%u_%p.bin", pid, addr);
                        FILE* f = fopen(filename, "wb");
                        if (f) {
                            fwrite(buffer, 1, bytesRead, f);
                            fclose(f);
                            printf("      ↳ Dumped to: %s\n", filename);
                        }
                    }
                }

                free(buffer);
            }
            addr = (LPCVOID)((ULONG_PTR)addr + mbi.RegionSize);
        } else {
            break;
        }
    }
}

void scan_processes_for_shellcode() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &pe)) {
        CloseHandle(snapshot);
        return;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
        if (hProcess) {
            wprintf(L"[*] Scanning PID %u (%s)\n", pe.th32ProcessID, pe.szExeFile);
            scan_process_memory(hProcess, pe.th32ProcessID);
            CloseHandle(hProcess);
        }
    } while (Process32Next(snapshot, &pe));

    CloseHandle(snapshot);
}
