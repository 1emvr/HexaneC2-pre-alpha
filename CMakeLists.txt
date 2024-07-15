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
        core/corelib/include/memory.hpp
        core/corelib/include/process.hpp
        core/corelib/include/cruntime.hpp
        core/corelib/include/network.hpp
        core/corelib/include/utils.hpp
        core/corelib/include/opsec.hpp
        core/corelib/include/names.hpp
        core/corelib/include/message.hpp
        core/corelib/include/stream.hpp
        core/corelib/include/parser.hpp
        inject/injectlib/injectlib.hpp
        core/implant/implant.hpp
        core/corelib/corelib.hpp
)
set(MAIN_FILES
        mods/src/EnumDotNetProcesses.cpp
        mods/src/RegDisableDefender.cpp
        mods/src/Impersonate.cpp

        core/corelib/src/process.cpp
        core/corelib/src/memory.cpp
        core/corelib/src/cruntime.cpp
        core/corelib/src/network.cpp
        core/corelib/src/utils.cpp
        core/corelib/src/opsec.cpp
        core/implant/implant.cpp
        core/corelib/src/message.cpp
        core/corelib/src/parser.cpp
        core/corelib/src/cipher.cpp
        core/corelib/src/stream.cpp
        core/corelib/src/commands.cpp
        loader/mainexe.cpp
        loader/dllmain.cpp
        inject/injectlib/injectlib.cpp
        inject/threadless/OpenFileExecute.cpp
)
add_executable(useful_modules ${INCLUDE_FILES} ${MAIN_FILES})
