#include "monolith.hpp"
EXTERN_C VOID Execute() {

    OFSTRUCT of_info = { };
    HFILE file  = OpenFile("./useless_file.txt", &of_info, OF_CREATE);

    CloseHandle((HANDLE)file);
}