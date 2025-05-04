cmake_minimum_required(VERSION 3.15)
project(RudimentaryAntimalwareScanner C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")

add_executable(antimalware
    main.c
    memory_scanner.c
    heuristics.c
)

# Link required Windows libraries
target_link_libraries(antimalware
    Advapi32
    Kernel32
    User32
    Psapi
)
