cmake_minimum_required(VERSION 4.1)
project(Project)

set(CMAKE_CXX_STANDARD 17)





add_executable(main main.cpp
        Protocal.h
)


if(WIN32)
    target_link_libraries(main ws2_32)
endif()
