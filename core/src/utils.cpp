#include <include/utils.hpp>
namespace Utils {

    DWORD64 GetTimeNow() {
        HEXANE

        FILETIME fileTime;
        LARGE_INTEGER largeInt;

        Ctx->win32.GetSystemTimeAsFileTime(&fileTime);

        largeInt.LowPart 	= fileTime.dwLowDateTime;
        largeInt.HighPart 	= fileTime.dwHighDateTime;

        return largeInt.QuadPart;
    }

    BOOL InWorkingHours() {
        HEXANE

        SYSTEMTIME SystemTime 	= {0};
        DWORD WorkingHours 		= Ctx->Config.WorkingHours;
        WORD StartHour 			= 0;
        WORD StartMinute 		= 0;
        WORD EndHour 			= 0;
        WORD EndMinute 			= 0;

        if (((WorkingHours >> 22) & 1) == 0) {
            return TRUE;
        }
        StartHour 	= (WorkingHours >> 17) & 0b011111;
        StartMinute = (WorkingHours >> 11) & 0b111111;
        EndHour 	= (WorkingHours >> 6) & 0b011111;
        EndMinute 	= (WorkingHours >> 0) & 0b111111;

        Ctx->win32.GetLocalTime(&SystemTime);

        if (
            (SystemTime.wHour < StartHour || SystemTime.wHour > EndHour) ||
            (SystemTime.wHour == StartHour && SystemTime.wMinute < StartMinute) ||
            (SystemTime.wHour == EndHour && SystemTime.wMinute > EndMinute)) {
            return FALSE;
        }

        return TRUE;
    }
};

namespace Random {
    using namespace Utils;

    DWORD RandomSleepTime() {
        HEXANE

        SYSTEMTIME SystemTime 	= {0};
        DWORD WorkingHours 		= Ctx->Config.WorkingHours;
        DWORD Sleeptime 		= Ctx->Config.Sleeptime * 1000;
        DWORD Variation 		= (Ctx->Config.Jitter * Sleeptime) / 100;
        DWORD Random 			= 0;
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

    constexpr int RandomSeed() {

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

        time.u.LowPart = *((DWORD*) (0x7FFE0000 + 0x14));
        time.u.HighPart = *((LONG*) (0x7FFE0000 + 0x1c));

        return (UINT_PTR) ((time.QuadPart - UNIX_TIME_START) / TICKS_PER_MILLISECOND);
    }

    DWORD RandomNumber32() {
        HEXANE

        auto seed = (DWORD) RandomSeed();

        seed = Ctx->Nt.RtlRandomEx(&seed);
        seed = Ctx->Nt.RtlRandomEx(&seed);
        seed = (seed % (LONG_MAX - 2 + 1)) + 2;

        return seed % 2 == 0
               ? seed
               : seed + 1;
    }

    BOOL RandomBool() {
        HEXANE

        auto seed = (DWORD) RandomSeed();

        seed = RandomSeed();
        seed = Ctx->Nt.RtlRandomEx(&seed);

        return seed % 2 == 0 ? TRUE : FALSE;
    }

    VOID Timeout(size_t ms) {
        // Courtesy of Illegacy & Shubakki:
        // https://www.legacyy.xyz/defenseevasion/windows/2022/07/04/abusing-shareduserdata-for-defense-evasion-and-exploitation.html

        HEXANE

        constexpr int defaultseed = RandomSeed();
        auto seed = Ctx->Nt.RtlRandomEx((DWORD*)&defaultseed);

        volatile size_t x = INTERVAL(seed);
        const unsigned long long end = Timestamp() + (x * ms);

        while (Timestamp() < end) { x += 1; }
        if (Timestamp() - end > 2000) {
            return;
        }
    }
}
