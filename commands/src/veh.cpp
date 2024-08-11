#include <core/monolith.hpp>
// https://github.com/Zer0Mem0ry/SignatureScanner/blob/master/SignatureScanner

struct LdrpVectorHandlerEntry {
	LdrpVectorHandlerEntry 		*Flink;
	LdrpVectorHandlerEntry 		*Blink;
	uint64_t 					Unknown1;
	uint64_t 					Unknown2;
	PVECTORED_EXCEPTION_HANDLER Handler;
};

struct LdrpVectorHandlerList {
	LdrpVectorHandlerEntry *First;
	LdrpVectorHandlerEntry *Last;
	SRWLOCK 				Lock;
};

struct module {
	UNICODE_STRING BaseDllName;
	LPVOID BaseAddress;
	LPVOID Entrypoint;
	ULONG Size;
};

class memory {
public:

	memory() {
		Process = NtCurrentProcess();
	}

	module* GetModuleHandle(const wchar_t *name) {

		PEB Peb 			= { };
		PEB_LDR_DATA *Ldr 	= { };
		CONTEXT Context 	= { };

		SIZE_T Read = 0;

		if (
			!GetThreadContext(NtCurrentThread(), &Context) ||
			!ReadProcessMemory(NtCurrentProcess(), REG_PEB_OFFSET(Context), (LPVOID)&Peb, sizeof(PEB), &Read) || Read != sizeof(PEB)) {
			return 0;
		}

		if (!(Ldr= Peb.Ldr)) {
			return 0;
		}

		for (LIST_ENTRY *Head = Ldr->InMemoryOrderModuleList.Flink; Head != &Ldr->InMemoryOrderModuleList; Head = Head->Flink) {
			PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(Head, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if (wcscmp(name, Entry->BaseDllName.Buffer)) {
				auto mod = R_CAST(module*, HeapAlloc(Process, 0, sizeof(module)));

				mod->BaseAddress 	= Entry->DllBase;
				mod->BaseDllName 	= Entry->BaseDllName;
				mod->Entrypoint 	= Entry->EntryPoint;
				mod->Size 			= Entry->SizeOfImage;

				return mod;
			}
		}

		return nullptr;
	}

	template<typename T>
	T ReadMemory(uintptr_t address) {

		T value = { };
		ReadProcessMemory(Process, R_CAST(LPCVOID, address), &value, sizeof(T), nullptr);
		return value;
	}

	template<typename T>
	T WriteMemory(uint32_t address, T data) {
		return WriteProcessMemory(Process, address, data, sizeof(T), nullptr);
	}

	bool CompareMemory(const uint8_t *data, const uint8_t *mask, const char *szMask) {

		for (; *szMask; ++szMask, ++data, ++mask) {
			if (*szMask == 0x78 && *data != *mask) {
				return FALSE;
			}
		}
		return (*szMask == 0x00);
	}

	uint32_t SignatureScan(uintptr_t start, uint32_t size, const char *signature, const char *mask) {

		uint8_t *data 	= R_CAST(uint8_t*, HeapAlloc(GetProcessHeap(), 0, size));
		size_t read 	= 0;

		if (!ReadProcessMemory(Process, R_CAST(void*, start), data, size, &read)) {
			return 0;
		}

		for (auto i = 0; i < size; i++) {
			if (CompareMemory(data + i, R_CAST(const uint8_t*, signature), mask)) {
				return start + i;
			}
		}

		memset(data, 0, size);
		HeapFree(GetProcessHeap(), 0, data);

		return 0;
	}
private:
	HANDLE Process = { };
};

class veh : memory {
public:

	uintptr_t VehGetFirstHandler(LPWSTR module) {

		memory mem;
		uint32_t match = 0;
		LdrpVectorHandlerList *handlers = { };

		const auto ntdll = mem.GetModuleHandle(module);
		if (!(match = mem.SignatureScan(R_CAST(uintptr_t, ntdll->BaseAddress), ntdll->Size, "\x99", "xxxxxxxx"))) {
			return 0;
		}

		match += 0xD;
		if (!(handlers = R_CAST(LdrpVectorHandlerList*, *R_CAST(int32_t*, match + (match + 0x3) + 0x7)))) {
			return 0;
		}

		HeapFree(GetProcessHeap(), 0, ntdll);
		return mem.ReadMemory<uintptr_t>(R_CAST(uintptr_t, handlers->First));
	}
};

