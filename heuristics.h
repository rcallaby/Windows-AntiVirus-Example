#ifndef HEURISTICS_H
#define HEURISTICS_H

double calculate_entropy(const unsigned char* data, size_t size);
int detect_shellcode_patterns(const unsigned char* data, size_t size);

#endif
