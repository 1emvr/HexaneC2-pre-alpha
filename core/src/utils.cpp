#include <core/include/utils.hpp>
namespace Utils {

    LPVOID RandomSelect(void** ptr_array) {
        int i = 0;
        while (true) {
            if (!ptr_array[i]) { break; }
            i++;
        }

        if (i > 0) { i -= 1; }
        return ptr_array[i % Utils::Random::RandomNumber32()];
    }

    VOID AppendBuffer(uint8_t **buffer, const uint8_t *const target, uint32_t *capacity, const uint32_t length) {
        HEXANE

        const auto new_buffer = B_PTR(x_realloc(*buffer, *capacity + length));
        if (!new_buffer) {
            return;
        }

        *buffer = new_buffer;
        x_memcpy(B_PTR(*buffer) + *capacity, target, length);
        *capacity += length;
    }

    VOID AppendPointerList(void **array[], void *pointer, uint32_t *count) {
       HEXANE

        const auto new_list = R_CAST(void**, x_realloc(*array, (*count + 1) * sizeof(void*)));
        if (!new_list) {
            return;
        }

        *array = new_list;
        (*array)[*count] = pointer;
        (*count)++;
    }

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

            FILETIME FileTime       = { };
            LARGE_INTEGER LargeInt  = { };

            Ctx->win32.GetSystemTimeAsFileTime(&FileTime);

            LargeInt.LowPart = FileTime.dwLowDateTime;
            LargeInt.HighPart = S_CAST(long, FileTime.dwHighDateTime);

            return LargeInt.QuadPart;
        }

        BOOL InWorkingHours() {
            HEXANE

            SYSTEMTIME SystemTime = { };

            uint32_t WorkingHours   = Ctx->config.hours;
            uint16_t StartHour      = 0;
            uint16_t StartMinute    = 0;
            uint16_t EndHour        = 0;
            uint16_t EndMinute      = 0;

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
            auto seed = Ctx->nt.RtlRandomEx(S_CAST(PULONG, &defaultseed));

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

            SYSTEMTIME sys_time = { };

            uint32_t work_hours = Ctx->config.hours;
            uint32_t sleeptime = Ctx->config.sleeptime * 1000;
            uint32_t variation = (Ctx->config.jitter * sleeptime) / 100;
            uint32_t random = 0;

            uint16_t start_hour = 0;
            uint16_t start_min = 0;
            uint16_t end_hour = 0;
            uint16_t end_min = 0;

            if (!Utils::Time::InWorkingHours()) {
                if (sleeptime) {

                    sleeptime = 0;
                    start_hour = (work_hours >> 17) & 0b011111;
                    start_min = (work_hours >> 11) & 0b111111;
                    end_hour = (work_hours >> 6) & 0b011111;
                    end_min = (work_hours >> 0) & 0b111111;

                    Ctx->win32.GetLocalTime(&sys_time);

                    if (sys_time.wHour == end_hour && sys_time.wMinute > end_min || sys_time.wHour > end_hour) {
                        sleeptime += (24 - sys_time.wHour - 1) * 60 + (60 - sys_time.wMinute);
                        sleeptime += start_hour * 60 + start_min;
                    } else {
                        sleeptime += (start_hour - sys_time.wHour) * 60 + (start_min - sys_time.wMinute);
                    }

                    sleeptime *= MS_PER_SECOND;
                }
            } else if (variation) {

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

            seed = Ctx->nt.RtlRandomEx(&seed);
            seed = Ctx->nt.RtlRandomEx(&seed);
            seed = seed % (LONG_MAX - 2 + 1) + 2;

            return seed % 2 == 0
                   ? seed
                   : seed + 1;
        }

        BOOL RandomBool() {
            HEXANE

            auto seed = RandomSeed();

            seed = RandomSeed();
            seed = Ctx->nt.RtlRandomEx(&seed);

            return seed % 2 == 0 ? TRUE : FALSE;
        }
    }
}
