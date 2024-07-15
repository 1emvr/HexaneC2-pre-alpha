cmake_minimum_required(VERSION 3.26)
project(useful_modules)

set(CMAKE_CXX_STANDARD 23)
enable_language(ASM_NASM)

set(SOURCE "/home/kali/Github/HexaneC2")
set(META "/usr/share/mingw-w64/include")

set(MODS "${SROUCE}/mods")
set(CORE "${SROUCE}/core")
set(INJ "${SROUCE}/inject")

include_directories(include ${SOURCE} ${META})

set(INCLUDE_FILES
        monolith.hpp
        ntimports.hpp
        core/include/memory.hpp
        core/include/process.hpp
        core/include/cruntime.hpp
        core/include/network.hpp
        core/include/utils.hpp
        core/include/opsec.hpp
        core/include/names.hpp
        core/include/message.hpp
        core/include/stream.hpp
        core/include/parser.hpp
        inject/include/injectlib.hpp
        core/implant/implant.hpp
        core/include/corelib.hpp
)
set(MAIN_FILES
        mods/src/EnumDotNetProcesses.cpp
        mods/src/RegDisableDefender.cpp
        mods/src/Impersonate.cpp

        core/src/process.cpp
        core/src/memory.cpp
        core/src/cruntime.cpp
        core/src/network.cpp
        core/src/utils.cpp
        core/src/opsec.cpp
        core/implant/implant.cpp
        core/src/message.cpp
        core/src/parser.cpp
        core/src/cipher.cpp
        core/src/stream.cpp
        core/src/commands.cpp
        inject/loader/mainexe.cpp
        inject/loader/dllmain.cpp
        inject/src/injectlib.cpp
        inject/threadless/OpenFileExecute.cpp
        inject/include/config.hpp
)
add_executable(useful_modules ${INCLUDE_FILES} ${MAIN_FILES})
