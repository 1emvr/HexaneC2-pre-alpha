cmake_minimum_required(VERSION 3.26)
project(Hexane-Implant)

set(CMAKE_CXX_STANDARD 23)
enable_language(ASM_NASM)

#set(MINGW "/usr/share/mingw-w64/include")
#set(META "/mnt/c/Program Files (x86)/Windows Kits/NETFXSDK/4.8/Include/um")

include_directories(include ${CMAKE_SOURCE_DIR} ${MINGW} ${META})

file(GLOB_RECURSE SOURCES "core/src/*.cpp")
file(GLOB_RECURSE INCLUDES "core/include/*.cpp")

add_executable(Hexane-Implant ${SOURCES} ${INCLUDES})