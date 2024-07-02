#include <monolith.hpp>
#include "loaders.hpp"

using namespace Loaders::Memory;
using namespace Loaders::Injection;

DLL_EXPORT BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved) {

    switch(reason) {
        case DLL_PROCESS_ATTACH:
            CreateThread(nullptr, 0, ROUTINE(Threadless), module, 0, nullptr);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
        default:
            break;
    }
    return TRUE;
}

