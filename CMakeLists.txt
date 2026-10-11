cmake_minimum_required(VERSION 3.10)
project(syn_raw_scanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

add_executable(syn_scanner main.cpp
        Protocol.h
)
target_compile_options(syn_scanner PRIVATE -Wall -Wextra)
target_link_libraries(syn_scanner PRIVATE Threads::Threads)
