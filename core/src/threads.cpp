#include <core/include/threads.hpp>
namespace Threads {

    HANDLE CreateUserThread(void* process, bool x64, void* entry, void* args, uint32_t* tid) {

        HANDLE      thread  = { };
        CLIENT_ID   cid     = { };

        PROC_THREAD_ATTRIBUTE_LIST thread_attr = { };

        thread_attr.Entry.Attribute     = ProcThreadAttributeValue(PsAttributeClientId, true, false, false);
        thread_attr.Entry.Size          = sizeof(CLIENT_ID);
        thread_attr.Entry.ValuePtr      = &cid;
        thread_attr.Length              = sizeof(PROC_THREAD_ATTRIBUTE_LIST);

        ntstatus = Ctx->nt.NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, nullptr, process, (PTHREAD_START_ROUTINE)entry, args, false, 0, 0, 0, (PS_ATTRIBUTE_LIST*)&thread_attr);
        if (NT_SUCCESS(ntstatus)) {
            if (tid) {
                *tid = U_PTR(cid.UniqueThread);
            }
        }
        else {
            // get error
        }

        return thread;
    }
}