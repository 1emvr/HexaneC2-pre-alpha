#include <core/monolith.hpp>
#include <core/include/stdlib.hpp>
#include <vector>
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

struct Module {
	UNICODE_STRING BaseDllName;
	LPVOID BaseAddress;
	LPVOID Entrypoint;
	ULONG Size;
};

struct HeapInfo {
	ULONG_PTR HeapId;
	DWORD ProcessId;
};

struct u32_block {
	uint32_t v0;
	uint32_t v1;
};

struct Ciphertext {
	uint32_t table[64];
};


template<typename T>
uint32_t GetHashFromString(T string, size_t length) {

	auto hash = FNV_OFFSET;

	if (string) {
		for (auto i = 0; i < length; i++) {
			hash ^= string[i];
			hash *= FNV_PRIME;
		}
	}
	return hash;
}


ULONG GetProcessIdByName(const char *proc) {
	HEXANE

	HANDLE hSnap = { };
	PROCESSENTRY32 entry = { };
	entry.dwSize = sizeof(PROCESSENTRY32);

	if (!(hSnap = Ctx->win32.CreateToolhelp32Snapshot(0x02, 0))) {
		return_defer(ERROR_INVALID_HANDLE);
	}

	if (Ctx->win32.Process32First(hSnap, &entry)) {
		while (Ctx->win32.Process32Next(hSnap, &entry)) {

			if (x_strcmp(proc, entry.szExeFile) == 0) {
				Ctx->Nt.NtClose(hSnap);
				return entry.th32ProcessID;
			}
		}
	}

	defer:
	if (hSnap) {
		Ctx->Nt.NtClose(hSnap);
	}

	return 0;
}

class MemoryOperations {
public:

	MemoryOperations(uint32_t access, uint32_t pid) {
		HEXANE

		HEAPLIST32 heaps = { };
		heaps.dwSize = sizeof(HEAPLIST32);

		if (!NT_SUCCESS(Process::NtOpenProcess(&process, access, pid))) {
			return;
		}

		auto snap = Ctx->win32.CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);
		if (snap == INVALID_HANDLE_VALUE) {
			return;
		}

		if (Heap32ListFirst(snap, &heaps)) {
			do {
				HeapInfo heap_info = { heaps.th32HeapID, heaps.th32ProcessID };
				m_heaps.push_back(heap_info);
			} while (Heap32ListNext(snap, &heaps));
		} else {
			return;
		}
	}

	~MemoryOperations() {
		m_heaps.clear();
	}

	Module* GetModuleHandle(uint32_t hash) {
		HEXANE

		PEB peb = { };
		CONTEXT thread_ctx = { };
		PEB_LDR_DATA *load = { };

		size_t read = 0;
		wchar_t lowercase[MAX_PATH] = { };

		if (
			!Ctx->Nt.NtGetContextThread(NtCurrentThread(), &thread_ctx) ||
			!Ctx->Nt.NtReadVirtualMemory(NtCurrentProcess(), REG_PEB_OFFSET(thread_ctx), (LPVOID) & peb, sizeof(PEB), &read)) {
			return nullptr;
		}

		if (read != sizeof(PEB)) {
			return nullptr;
		}

		load = peb.Ldr;
		for (auto head = load->InMemoryOrderModuleList.Flink; head != &load->InMemoryOrderModuleList; head = head->Flink) {
			auto entry = CONTAINING_RECORD(head, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if (hash - GetHashFromString(x_wcsToLower(lowercase, entry->BaseDllName.Buffer), entry->BaseDllName.Length) == 0) {
				auto mod = R_CAST(Module * , Ctx->Nt.RtlAllocateHeap(process, 0, sizeof(Module)));

				mod->BaseAddress = entry->DllBase;
				mod->BaseDllName = entry->BaseDllName;
				mod->Entrypoint = entry->EntryPoint;
				mod->Size = entry->SizeOfImage;

				return mod;
			}
		}

		return nullptr;
	}

	uintptr_t GetSymbolAddress(void *base, uint32_t hash) {

		uintptr_t address        = { };
		char lowercase[MAX_PATH]  = { };

		auto dos_head = IMAGE_DOS_HEADER(base);
		auto nt_head = IMAGE_NT_HEADERS(base, dos_head);
		auto exports = IMAGE_EXPORT_DIRECTORY(dos_head, nt_head);

		if (exports->AddressOfNames) {
			auto ords = RVA(PWORD, base, exports->AddressOfNameOrdinals);
			auto fns = RVA(PULONG, base, exports->AddressOfFunctions);
			auto names = RVA(PULONG, base, exports->AddressOfNames);

			for (auto i = 0; i < exports->NumberOfNames; i++) {
				auto name = RVA(char *, base, (long) names[i]);

				x_memset(lowercase, 0, MAX_PATH);

				if (hash - GetHashFromString(x_mbsToLower(lowercase, name), x_strlen(name)) == 0) {
					address = R_CAST(uintptr_t, RVA(uint32_t *, base, fns[ords[i]]));
					break;
				}
			}
		}

		return address;
	}

	static bool SignatureMatch(const uint8_t *data, const uint8_t *signature, const char *mask) {

		for (; *mask; ++mask, ++data, ++signature) {
			if (*mask == 0x78 && *data != *signature) {
				return FALSE;
			}
		}
		return (*mask == 0x00);
	}

	static void PatchMemory(byte *dst, byte const *src, int d_iter, int s_iter, size_t n) {

		for (auto i = 0; i < n; i++) {
			(dst)[d_iter] = (src)[s_iter];
		}
	}

	template<typename T>
	bool ReadMemory(T buffer, uintptr_t address) {
		HEXANE

		if (!NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(process, R_CAST(LPVOID, address), &buffer, sizeof(T), nullptr))) {
			return false;
		}
		return true;
	}

	template<typename T>
	bool WriteMemory(T buffer, uint32_t address) {
		HEXANE

		if (!NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(process, address, buffer, sizeof(T), nullptr))) {
			return false;
		}
		return true;
	}

	uintptr_t SignatureScan(uintptr_t start, uint32_t size, const char *signature, const char *mask) {
		HEXANE

		uintptr_t address = 0;
		size_t read	= 0;

		auto *buffer = R_CAST(uint8_t*, Ctx->Nt.RtlAllocateHeap(GetProcessHeap(), 0, size));
		if (!NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(process, R_CAST(void *, start), buffer, size, &read))) {
			return 0;
		}

		for (auto i = 0; i < size; i++) {
			if (SignatureMatch(buffer + i, R_CAST(const uint8_t*, signature), mask)) {
				address = start + i;
				break;
			}
		}

		x_memset(buffer, 0, size);
		Ctx->Nt.RtlFreeHeap(GetProcessHeap(), 0, buffer);

		return address;
	}

private:
	void *process = { };
	std::vector<HeapInfo> m_heaps = { };

};


class Veh {
public:
	explicit Veh(uint32_t pid) : mem(ACCESS_VEH, pid) { }

	uintptr_t VehGetFirstHandler(wchar_t *name, const char *signature, const char *mask) {
		HEXANE

		LdrpVectorHandlerList *handlers = { };
		uintptr_t handler = { };
		uint32_t match = 0;

		const auto ntdll = mem.GetModuleHandle(GetHashFromString(name, x_wcslen(name)));

		if (!(match = mem.SignatureScan(R_CAST(uintptr_t, ntdll->BaseAddress), ntdll->Size, signature, mask))) {
			return 0;
		}

		match += 0xD;
		if (!(handlers = R_CAST(LdrpVectorHandlerList*, *R_CAST(int32_t*, match + (match + 0x3) + 0x7)))) {
			return 0;
		}

		Ctx->Nt.RtlFreeHeap(GetProcessHeap(), 0, ntdll);
		mem.ReadMemory(handler, R_CAST(uintptr_t, handlers->First));

		return handler;
	}
private:
	MemoryOperations mem;
};

int main() {
	HEXANE

	Veh v(GetProcessIdByName("blobrunner64.exe"));
	auto handler = v.VehGetFirstHandler(L"ntdll.dll", "\x00\x00\x00\x00\x00\x00\x00\x00", "xx0000xx");
	x_memset(&handler, 0, sizeof(uintptr_t));
}