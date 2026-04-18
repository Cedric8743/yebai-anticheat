cmake_minimum_required(VERSION 3.10)
project(YeBaiAntiCheat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 资源文件
enable_language(RC)
set(RC_COMPILER windres)

# Windows 程序，GUI 模式
add_definitions(-D_UNICODE)
add_definitions(-DUNICODE)

# 关闭控制台 (/SUBSYSTEM:WINDOWS)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_EXE_LINKER_FLAGS "-static -mwindows")
else()
    set(CMAKE_EXE_LINKER_FLAGS "-mwindows")
endif()

add_executable(YeBaiAntiCheat WIN32
    main.cpp
    resource.rc
)

target_link_libraries(YeBaiAntiCheat
    wininet
    advapi32
    comctl32
)
