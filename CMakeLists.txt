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
set(CORELIB "${CORE}/corelib")
set(IMPLANT "${CORE}/implant")

include_directories(include ${SOURCE} ${MINGW} ${META})

set(INCLUDES
        "${CORE}/monolith.hpp"
        "${CORE}/ntimports.hpp"
        "${CORELIB}/corelib.hpp"
        "${CORELIB}/include/process.hpp"
        "${CORELIB}/include/memory.hpp"
        "${CORELIB}/include/cruntime.hpp"
        "${CORELIB}/include/network.hpp"
        "${CORELIB}/include/utils.hpp"
        "${CORELIB}/include/opsec.hpp"
        "${CORELIB}/include/message.hpp"
        "${CORELIB}/include/parser.hpp"
        "${CORELIB}/include/cipher.hpp"
        "${CORELIB}/include/stream.hpp"
        "${CORELIB}/include/commands.hpp"
        "${CORELIB}/include/inject.hpp"
)
set(MAIN_FILES
        "${CORELIB}/src/process.cpp"
        "${CORELIB}/src/memory.cpp"
        "${CORELIB}/src/cruntime.cpp"
        "${CORELIB}/src/network.cpp"
        "${CORELIB}/src/utils.cpp"
        "${CORELIB}/src/opsec.cpp"
        "${CORELIB}/src/message.cpp"
        "${CORELIB}/src/parser.cpp"
        "${CORELIB}/src/cipher.cpp"
        "${CORELIB}/src/stream.cpp"
        "${CORELIB}/src/commands.cpp"
        "${LOADER}/src/mainexe.cpp"
        "${LOADER}/src/dllmain.cpp"
        "${INJECT}/injectlib/src/injectlib.cpp"
        "${INJECT}/threadless/src/OpenFileExecute.cpp"
        "${IMPLANT}/src/implant.cpp"
        "${CORELIB}/src/inject.cpp"
        mods/src/EnumDotNetProcesses.cpp
)
add_executable(Hexane-Implant ${MAIN_FILES} ${INCLUDES})