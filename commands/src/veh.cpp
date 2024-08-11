#include <core/monolith.hpp>
#include <core/include/stdlib.hpp>
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


struct u32_block {
	uint32_t v0;
	uint32_t v1;
};

struct Ciphertext {
	uint32_t table[64];
};



class memory {
public:

	memory() {
		Process = NtCurrentProcess();
	}

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

	Module* GetModuleHandle(uint32_t hash) {
		HEXANE

		PEB Peb 			= {};
		PEB_LDR_DATA *Ldr 	= {};
		CONTEXT Context 	= {};

		size_t Read 		= 0;
		wchar_t lowName[MAX_PATH] = { };

		if (
			!Ctx->Nt.NtGetContextThread(NtCurrentThread(), &Context) ||
			!Ctx->Nt.NtReadVirtualMemory(NtCurrentProcess(), REG_PEB_OFFSET(Context), (LPVOID) & Peb, sizeof(PEB), &Read)) {
			return nullptr;
		}

		if (Read != sizeof(PEB)) {
			return nullptr;
		}

		Ldr = Peb.Ldr;
		for (auto Head = Ldr->InMemoryOrderModuleList.Flink; Head != &Ldr->InMemoryOrderModuleList; Head = Head->Flink) {
			auto Entry = CONTAINING_RECORD(Head, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

			if (hash - GetHashFromString(x_wcsToLower(lowName, Entry->BaseDllName.Buffer), Entry->BaseDllName.Length) == 0) {
				auto mod = R_CAST(Module * , HeapAlloc(Process, 0, sizeof(Module)));

				mod->BaseAddress = Entry->DllBase;
				mod->BaseDllName = Entry->BaseDllName;
				mod->Entrypoint = Entry->EntryPoint;
				mod->Size = Entry->SizeOfImage;

				return mod;
			}
		}

		return nullptr;
	}

	uintptr_t GetSymbolAddress(void *Base, uint32_t Hash) {

		uintptr_t Export        = { };
		char lowName[MAX_PATH]  = { };

		auto DosHead    = IMAGE_DOS_HEADER(Base);
		auto NtHead     = IMAGE_NT_HEADERS(Base, DosHead);
		auto Exports    = IMAGE_EXPORT_DIRECTORY(DosHead, NtHead);

		if (Exports->AddressOfNames) {
			auto Ords   = RVA(PWORD, Base, Exports->AddressOfNameOrdinals);
			auto Fns    = RVA(PULONG, Base, Exports->AddressOfFunctions);
			auto Names  = RVA(PULONG, Base, Exports->AddressOfNames);

			for (auto i = 0; i < Exports->NumberOfNames; i++) {
				auto Name = RVA(char *, Base, (long) Names[i]);

				x_memset(lowName, 0, MAX_PATH);

				if (Hash - GetHashFromString(x_mbsToLower(lowName, Name), x_strlen(Name)) == 0) {
					Export = R_CAST(uintptr_t, RVA(uint32_t *, Base, Fns[Ords[i]]));
					break;
				}
			}
		}

		return Export;
	}

	static bool SignatureMatch(const uint8_t *data, const uint8_t *mask, const char *szMask) {

		for (; *szMask; ++szMask, ++data, ++mask) {
			if (*szMask == 0x78 && *data != *mask) {
				return FALSE;
			}
		}
		return (*szMask == 0x00);
	}

	static void PatchMemory(byte *dst, byte const *src, int d_iter, int s_iter, size_t n) {

		for (auto iter = 0; iter < n; iter++) {
			(dst)[d_iter] = (src)[s_iter];
		}
	}

	template<typename T>
	int32_t ReadMemory(uintptr_t address, T buffer) {
		HEXANE
		return Ctx->Nt.NtReadVirtualMemory(Process, R_CAST(LPVOID, address), &buffer, sizeof(T), nullptr);
	}

	template<typename T>
	int32_t WriteMemory(uint32_t address, T data) {
		HEXANE
		return Ctx->Nt.NtWriteVirtualMemory(Process, address, data, sizeof(T), nullptr);
	}

	uint32_t SignatureScan(uintptr_t start, uint32_t size, const char *signature, const char *mask) {
		HEXANE

		uintptr_t address = 0;
		size_t read	= 0;

		auto *buffer = R_CAST(uint8_t*, Ctx->Nt.RtlAllocateHeap(GetProcessHeap(), 0, size));
		if (!NT_SUCCESS(Ctx->Nt.NtReadVirtualMemory(Process, R_CAST(void *, start), buffer, size, &read))) {
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
	HANDLE Process = { };
};

class veh : memory {
public:

	uintptr_t VehGetFirstHandler(LPWSTR name) {

		memory mem;
		uint32_t match = 0;
		LdrpVectorHandlerList *handlers = { };
		uintptr_t handler = { };

		const auto ntdll = mem.GetModuleHandle(GetHashFromString(name, x_wcslen(name)));
		if (!(match = mem.SignatureScan(R_CAST(uintptr_t, ntdll->BaseAddress), ntdll->Size, "\x00\x00\x00\x00\x00\x00\x00\x00", "xxxxxxxx"))) {
			return 0;
		}

		match += 0xD;
		if (!(handlers = R_CAST(LdrpVectorHandlerList*, *R_CAST(int32_t*, match + (match + 0x3) + 0x7)))) {
			return 0;
		}

		HeapFree(GetProcessHeap(), 0, ntdll);
		mem.ReadMemory(R_CAST(uintptr_t, handlers->First), handler);

		return (uintptr_t) handler;
	}
};

int main(void) {

}