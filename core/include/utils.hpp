#ifndef HEXANE_CORELIB_UTILS_HPP
#define HEXANE_CORELIB_UTILS_HPP

#define MS_PER_SECOND	1000
#define INTERVAL(x)     (x % 26)
#define SECONDS(x)      (x * MS_PER_SECOND)
#define MINUTES(x)      (x * SECONDS(64))

#define FNV_OFFSET      (CONST unsigned int) 2166136261
#define FNV_PRIME	    (CONST unsigned int) 16777619

#define WNULTERM 	    0x00000000
#define NULTERM		    0x00
#define PERIOD          0x2E
#define BSLASH          0x5C
#define ASTER           0x2A

#include <core/corelib.hpp>

namespace Utils {

	BOOL
	FUNCTION
	    WriteToDisk(CONST WCHAR *path, CONST UINT8 *data, SIZE_T size);

	BOOL
	FUNCTION
	    ReadFromDisk(CONST WCHAR *path, UINT8 *data, SIZE_T size);

	BOOL
	FUNCTION
	    DestroyFileData(CONST WCHAR *path, SIZE_T size);

    VOID
    FUNCTION
        AppendBuffer(UINT8 **buffer, CONST UINT8 *target, UINT32 *capacity, UINT32 length);

    VOID
    FUNCTION
        AppendPointerList(VOID **array[], VOID *pointer, UINT32 *count);

	BOOL
	FUNCTION
	    ReadMemory(HANDLE handle, VOID *dst, VOID *src, UINT_PTR size);

    namespace Scanners {
        BOOL
        FUNCTION
            MapScan(HASH_MAP *map, UINT32 id, VOID **pointer);

        BOOL
        FUNCTION
            SigCompare(CONST UINT8 *data, CONST CHAR *signature, CONST CHAR *mask);

        UINT_PTR
        FUNCTION
            RelocateExport(VOID *process, CONST VOID *target, SIZE_T size);

        UINT_PTR
        FUNCTION
            SignatureScan(HANDLE process, UINT_PTR base, UINT32 size, CONST CHAR *signature, CONST CHAR *mask);

		UINT_PTR
		FUNCTION
		    SignatureScanSection(HANDLE handle, CONST CHAR *sec_name, UINT_PTR base, CONST CHAR *signature, CONST CHAR *mask);
    }

    namespace Time {
        UINT64
        FUNCTION
            GetTimeNow();

        BOOL
        FUNCTION
            InWorkingHours();

        VOID
        FUNCTION
            Timeout(SIZE_T ms);

    }

    namespace Random {
        UINT32
        FUNCTION
            RandomSleepTime();

        UINT32
        FUNCTION
            RandomSeed();

        UINT_PTR
        FUNCTION
            Timestamp();

        UINT32
        FUNCTION
            RandomNumber32();

        BOOL
        FUNCTION
            RandomBool();
    }
}

#endif //HEXANE_CORELIB_UTILS_HPP
