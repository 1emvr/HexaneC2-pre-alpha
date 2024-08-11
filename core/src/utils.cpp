#include <core/include/utils.hpp>
namespace Utils {

    ULONG GetHashFromStringA(char const *string, size_t length) {

        auto hash = FNV_OFFSET;
        if (string) {
            for (auto i = 0; i < length; i++) {
                hash ^= string[i];
                hash *= FNV_PRIME;
            }
        }
        return hash;
    }

    ULONG GetHashFromStringW(wchar_t const *string, size_t length) {

        auto hash = FNV_OFFSET;
        if (string) {
            for (auto i = 0; i < length; i++) {
                hash ^= string[i];
                hash *= FNV_PRIME;
            }
        }
        return hash;
    }

    namespace Time {

        ULONG64 GetTimeNow() {
            HEXANE

            FILETIME FileTime = {};
            LARGE_INTEGER LargeInt = {};

            Ctx->win32.GetSystemTimeAsFileTime(&FileTime);

            LargeInt.LowPart = FileTime.dwLowDateTime;
            LargeInt.HighPart = S_CAST(long, FileTime.dwHighDateTime);

            return LargeInt.QuadPart;
        }

        BOOL InWorkingHours() {
            HEXANE

            SYSTEMTIME SystemTime = {0};

            uint32_t WorkingHours = Ctx->Config.WorkingHours;
            uint16_t StartHour = 0;
            uint16_t StartMinute = 0;
            uint16_t EndHour = 0;
            uint16_t EndMinute = 0;

            if (((WorkingHours >> 22) & 1) == 0) {
                return TRUE;
            }

            StartHour = (WorkingHours >> 17) & 0b011111;
            StartMinute = (WorkingHours >> 11) & 0b111111;
            EndHour = (WorkingHours >> 6) & 0b011111;
            EndMinute = (WorkingHours >> 0) & 0b111111;

            Ctx->win32.GetLocalTime(&SystemTime);

            if (
                (SystemTime.wHour < StartHour || SystemTime.wHour > EndHour) ||
                (SystemTime.wHour == StartHour && SystemTime.wMinute < StartMinute) ||
                (SystemTime.wHour == EndHour && SystemTime.wMinute > EndMinute)) {
                return FALSE;
            }

            return TRUE;
        }

        VOID Timeout(size_t ms) {
            HEXANE
            // Courtesy of Illegacy & Shubakki:
            // https://www.legacyy.xyz/defenseevasion/windows/2022/07/04/abusing-shareduserdata-for-defense-evasion-and-exploitation.html

            auto defaultseed = Utils::Random::RandomSeed();
            auto seed = Ctx->Nt.RtlRandomEx(S_CAST(PULONG, &defaultseed));

            volatile size_t x = INTERVAL(seed);
            const uintptr_t end = Utils::Random::Timestamp() + (x * ms);

            while (Utils::Random::Timestamp() < end) { x += 1; }
            if (Utils::Random::Timestamp() - end > 2000) {
                return;
            }
        }
    }

    namespace Random {

        ULONG RandomSleepTime() {
            HEXANE

            SYSTEMTIME SystemTime = { };

            uint32_t WorkingHours = Ctx->Config.WorkingHours;
            uint32_t Sleeptime = Ctx->Config.Sleeptime * 1000;
            uint32_t Variation = (Ctx->Config.Jitter * Sleeptime) / 100;
            uint32_t Random = 0;

            uint16_t StartHour = 0;
            uint16_t StartMinute = 0;
            uint16_t EndHour = 0;
            uint16_t EndMinute = 0;

            if (!Utils::Time::InWorkingHours()) {
                if (Sleeptime) {

                    Sleeptime = 0;
                    StartHour = (WorkingHours >> 17) & 0b011111;
                    StartMinute = (WorkingHours >> 11) & 0b111111;
                    EndHour = (WorkingHours >> 6) & 0b011111;
                    EndMinute = (WorkingHours >> 0) & 0b111111;

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
            const size_t epoch = 0x019DB1DED53E8000;
            const size_t ms_ticks = 1000;

            time.u.LowPart = *R_CAST(uint32_t*, 0x7FFE0000 + 0x14);
            time.u.HighPart = *R_CAST(int32_t*, 0x7FFE0000 + 0x1c);

            return (time.QuadPart - epoch) / ms_ticks;
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

    }
}