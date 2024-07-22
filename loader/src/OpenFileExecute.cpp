#include "core/monolith.hpp"
#pragma comment(lib, "kernel32")

EXTERN_C VOID Execute() {

    OFSTRUCT ofInfo = { };
    HFILE File  = OpenFile("doesnotexist.txt", &ofInfo, OF_CREATE);

    CloseHandle(RCAST(HANDLE, File));
}