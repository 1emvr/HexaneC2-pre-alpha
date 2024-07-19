#include <core/corelib/include/utils.hpp>
namespace Utils {

    ULONG64 GetTimeNow() {
        HEXANE

        FILETIME FileTime;
        LARGE_INTEGER LargeInt;

        Ctx->win32.GetSystemTimeAsFileTime(&FileTime);

        LargeInt.LowPart = FileTime.dwLowDateTime;
        LargeInt.HighPart = SCAST(LONG, FileTime.dwHighDateTime);

        return LargeInt.QuadPart;
    }

    BOOL InWorkingHours() {
        HEXANE

        SYSTEMTIME SystemTime = {0};
        ULONG WorkingHours  = Ctx->Config.WorkingHours;
        WORD StartHour      = 0;
        WORD StartMinute    = 0;
        WORD EndHour        = 0;
        WORD EndMinute      = 0;

        if (((WorkingHours >> 22) & 1) == 0) {
            return TRUE;
        }

        StartHour   = (WorkingHours >> 17) & 0b011111;
        StartMinute = (WorkingHours >> 11) & 0b111111;
        EndHour     = (WorkingHours >> 6) & 0b011111;
        EndMinute   = (WorkingHours >> 0) & 0b111111;

        Ctx->win32.GetLocalTime(&SystemTime);

        if (
            (SystemTime.wHour < StartHour || SystemTime.wHour > EndHour) ||
            (SystemTime.wHour == StartHour && SystemTime.wMinute < StartMinute) ||
            (SystemTime.wHour == EndHour && SystemTime.wMinute > EndMinute)) {
            return FALSE;
        }

        return TRUE;
    }

    ULONG GetHashFromStringA(CONST LPSTR String, SIZE_T Length) {

        auto hash = FNV_OFFSET;

        if (String) {
            for (auto i = 0; i < Length; i++) {
                hash ^= String[i];
                hash *= FNV_PRIME;
            }
        }
        return hash;
    }

    ULONG GetHashFromStringW(CONST LPWSTR String, SIZE_T Length) {

        auto hash = FNV_OFFSET;

        if (String) {
            for (auto i = 0; i < Length; i++) {
                hash ^= String[i];
                hash *= FNV_PRIME;
            }
        }
        return hash;
    }
}

namespace Random {
    using namespace Utils;

    ULONG RandomSleepTime() {
        HEXANE

        SYSTEMTIME SystemTime 	= {0};
        ULONG WorkingHours 		= Ctx->Config.WorkingHours;
        ULONG Sleeptime 		= Ctx->Config.Sleeptime * 1000;
        ULONG Variation 		= (Ctx->Config.Jitter * Sleeptime) / 100;
        ULONG Random 			= 0;
        WORD StartHour 			= 0;
        WORD StartMinute 		= 0;
        WORD EndHour 			= 0;
        WORD EndMinute 			= 0;

        if (!InWorkingHours()) {
            if (Sleeptime) {

                Sleeptime   = 0;
                StartHour 	= (WorkingHours >> 17) & 0b011111;
                StartMinute = (WorkingHours >> 11) & 0b111111;
                EndHour 	= (WorkingHours >> 6) & 0b011111;
                EndMinute 	= (WorkingHours >> 0) & 0b111111;

                Ctx->win32.GetLocalTime(&SystemTime);

                if (SystemTime.wHour == EndHour && SystemTime.wMinute > EndMinute || SystemTime.wHour > EndHour) {
                    Sleeptime += (24 - SystemTime.wHour - 1) * 60 + (60 - SystemTime.wMinute);
                    Sleeptime += StartHour * 60 + StartMinute;
                } else {
                    Sleeptime += (StartHour - SystemTime.wHour) * 60 + (StartMinute - SystemTime.wMinute);
                }

                Sleeptime *= MS_PER_SECOND;
            }
        } else if (Variation) {

            Random = RandomNumber32();
            Random = Random % Variation;

            if (RandomBool()) {
                Sleeptime += Random;
            } else {
                Sleeptime -= Random;
            }
        }

        return Sleeptime;
    }

    ULONG RandomSeed() {

        return 'A2' * -40271 +
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

        time.u.LowPart = *RCAST(uint32_t*, 0x7FFE0000 + 0x14);
        time.u.HighPart = *RCAST(int32_t*, 0x7FFE0000 + 0x1c);

        return (time.QuadPart - UNIX_TIME_START) / TICKS_PER_MILLISECOND;
    }

    ULONG RandomNumber32() {
        HEXANE

        auto seed = RandomSeed();

        seed = Ctx->Nt.RtlRandomEx(&seed);
        seed = Ctx->Nt.RtlRandomEx(&seed);
        seed = seed % (LONG_MAX - 2 + 1) + 2;

        return seed % 2 == 0
               ? seed
               : seed + 1;
    }

    BOOL RandomBool() {
        HEXANE

        auto seed = RandomSeed();

        seed = RandomSeed();
        seed = Ctx->Nt.RtlRandomEx(&seed);

        return seed % 2 == 0 ? TRUE : FALSE;
    }

    VOID Timeout(size_t ms) {
        // Courtesy of Illegacy & Shubakki:
        // https://www.legacyy.xyz/defenseevasion/windows/2022/07/04/abusing-shareduserdata-for-defense-evasion-and-exploitation.html

        HEXANE

        auto defaultseed = RandomSeed();
        auto seed = Ctx->Nt.RtlRandomEx(SCAST(PULONG, &defaultseed));

        volatile size_t x = INTERVAL(seed);
        const uintptr_t end = Timestamp() + (x * ms);

        while (Timestamp() < end) { x += 1; }
        if (Timestamp() - end > 2000) {
            return;
        }
    }
}
