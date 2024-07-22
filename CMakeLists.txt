cmake_minimum_required(VERSION 3.26)
project(Hexane-Implant)

set(CMAKE_CXX_STANDARD 23)
enable_language(ASM_NASM)

set(SOURCE "/home/lemur/Github/HexaneC2")
set(MINGW "/usr/share/mingw-w64/include")
set(META "/mnt/c/Program Files (x86)/Windows Kits/NETFXSDK/4.8/Include/um")

set(CORE "${SOURCE}/core")
set(INJECT "${SOURCE}/inject")
set(LOADER "${SOURCE}/loader")
set(IMPLANT "${SOURCE}/implant")

include_directories(include ${SOURCE} ${MINGW} ${META})

set(INCLUDES
        "${CORE}/monolith.hpp"
        "${CORE}/ntimports.hpp"
        "${CORE}/corelib.hpp"
        "${CORE}/include/process.hpp"
        "${CORE}/include/memory.hpp"
        "${CORE}/include/cruntime.hpp"
        "${CORE}/include/network.hpp"
        "${CORE}/include/utils.hpp"
        "${CORE}/include/opsec.hpp"
        "${CORE}/include/message.hpp"
        "${CORE}/include/parser.hpp"
        "${CORE}/include/cipher.hpp"
        "${CORE}/include/stream.hpp"
        "${CORE}/include/commands.hpp"
        "${CORE}/include/inject.hpp"
)
set(MAIN_FILES
        "${CORE}/src/process.cpp"
        "${CORE}/src/memory.cpp"
        "${CORE}/src/cruntime.cpp"
        "${CORE}/src/network.cpp"
        "${CORE}/src/utils.cpp"
        "${CORE}/src/opsec.cpp"
        "${CORE}/src/message.cpp"
        "${CORE}/src/parser.cpp"
        "${CORE}/src/cipher.cpp"
        "${CORE}/src/stream.cpp"
        "${CORE}/src/commands.cpp"
        "${CORE}/src/inject.cpp"
        "${LOADER}/src/main.cpp"
        "${LOADER}/src/dllmain.cpp"
        "${LOADER}/src/rsrc.cpp"
        "${LOADER}/src/OpenFileExecute.cpp"
        "${IMPLANT}/src/implant.cpp"
        mods/src/EnumDotNetProcesses.cpp
        core/src/inject.cpp
)
add_executable(Hexane-Implant ${MAIN_FILES} ${INCLUDES})