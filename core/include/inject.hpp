#ifndef HEXANE_IMPLANT_INJECT_HPP
#define HEXANE_IMPLANT_INJECT_HPP
#include <core/corelib.hpp>

namespace Injection {
    VOID
    FUNCTION
        Threadless(CONST THREADLESS &writer, VOID *shellcode, SIZE_T n_shellcode, SIZE_T total);

    namespace Veh {
        UINT_PTR
        FUNCTION
            GetFirstHandler(LDR_DATA_TABLE_ENTRY *module, CONST CHAR *signature, CONST CHAR *mask);

        UINT_PTR
        FUNCTION
            PointerEncodeDecode(UINT_PTR CONST &pointer, BOOL encode);

        BOOL
        FUNCTION
            OverwriteFirstHandler(VEH_WRITER CONST &writer);
    }
}
#endif //HEXANE_IMPLANT_INJECT_HPP
