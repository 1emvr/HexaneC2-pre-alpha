cmake_minimum_required(VERSION 3.26)
project(useful_modules)

set(CMAKE_CXX_STANDARD 23)
enable_language(ASM_NASM)

set(SOURCE "C:/Users/lemur/CLionProjects/HexaneC2")
set(META "C:/Program Files (x86)/Windows Kits/NETFXSDK/4.8/Include/um")

include_directories(include ${SOURCE} ${META})

set(INCLUDE_FILES
        core/include/monolith.hpp
        core/include/ntimports.hpp
        core/include/memory.hpp
        core/include/process.hpp
        core/include/cruntime.hpp
        core/include/network.hpp
        core/include/hash.hpp
        core/include/utils.hpp
        core/include/opsec.hpp
        core/include/names.hpp
        core/include/message.hpp
        core/include/stream.hpp
        core/include/parser.hpp
)
set(MAIN_FILES
        mods/src/EnumDotNetProcesses.cpp
        mods/src/RegDisableDefender.cpp
        mods/src/Impersonate.cpp

        core/src/process.cpp
        core/src/memory.cpp
        core/src/cruntime.cpp
        core/src/network.cpp
        core/src/hash.cpp
        core/src/utils.cpp
        core/src/opsec.cpp
        core/src/core.cpp
        core/src/message.cpp
        core/include/context.hpp
        core/src/context.cpp
        core/src/parser.cpp
        core/src/cipher.cpp
        loader/DllMain.cpp
        loader/loaders.cpp
        core/src/stream.cpp
        core/src/commands.cpp
        implant/MainExe.cpp
)
add_executable(useful_modules ${INCLUDE_FILES} ${MAIN_FILES})
