#include <stdio.h>
#include "memory_scanner.h"

int main() {
    printf("=== Rudimentary Shellcode Detector (C, Windows) ===\n\n");
    scan_processes_for_shellcode();
    printf("\n[✓] Scan complete.\n");
    return 0;
}
