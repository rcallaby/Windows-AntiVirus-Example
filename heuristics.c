#include <math.h>
#include "heuristics.h"

double calculate_entropy(const unsigned char* data, size_t size) {
    if (size == 0) return 0.0;

    int counts[256] = {0};
    for (size_t i = 0; i < size; i++) counts[data[i]]++;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i]) {
            double p = (double)counts[i] / size;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

int detect_shellcode_patterns(const unsigned char* data, size_t size) {
    size_t nop_count = 0, int3_count = 0;

    for (size_t i = 0; i < size; i++) {
        if (data[i] == 0x90) nop_count++;     // NOP sled
        if (data[i] == 0xCC) int3_count++;     // INT3 breakpoint
    }

    return (nop_count > 50 || int3_count > 20);
}
