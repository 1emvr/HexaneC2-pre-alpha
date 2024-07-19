cmake_minimum_required(VERSION 3.26)
project(Hexane-Implant)

set(CMAKE_CXX_STANDARD 23)
enable_language(ASM_NASM)

set(SOURCE "/home/kali/Github/HexaneC2")
set(META "/usr/share/mingw-w64/include")

set(CORE "${SOURCE}/core")
set(INJECT "${SOURCE}/inject")
set(LOADER "${SOURCE}/loader")
set(CORELIB "${CORE}/corelib")
set(IMPLANT "${CORE}/implant")

include_directories(include ${SOURCE})

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
        "${LOADER}/mainexe.cpp"
        "${LOADER}/dllmain.cpp"
        "${INJECT}/injectlib/injectlib.cpp"
        "${INJECT}/threadless/OpenFileExecute.cpp"
        "${IMPLANT}/implant.cpp"
)
add_executable(Hexane-Implant ${MAIN_FILES} ${INCLUDES})