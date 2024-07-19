#include <core/monolith.hpp>
EXTERN_C VOID Execute() {

    OFSTRUCT of_info = { };
    HFILE file  = OpenFile("document.txt", &of_info, OF_CREATE);

    CloseHandle(RCAST(HANDLE, file));
}