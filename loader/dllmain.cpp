#include <core/include/monolith.hpp>
#include <core/include/context.hpp>
using namespace Memory;

EXTERN_C VOID Start();

DLL_EXPORT BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved) {

    switch(reason) {
        case DLL_PROCESS_ATTACH:
            CreateThread(nullptr, 0, ROUTINE(Start), nullptr, 0, nullptr);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
        default:
            break;
    }
    return TRUE;
}

