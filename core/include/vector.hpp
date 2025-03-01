#include <core/corelib.hpp>

struct LATE_LOAD_ENTRY {
	UINT32 hash;
	PEXECUTABLE mod;
};

struct VECTOR {
    LATE_LOAD_ENTRY* data;           
    SIZE_T capacity;   
    SIZE_T length;     
};

VOID FUNCTION init_vector(VECTOR& vec);
VOID FUNCTION push_back(VECTOR& vec, CONST LATE_LOAD_ENTRY& value);
LATE_LOAD_ENTRY& FUNCTION vec_at(VECTOR& vec, SIZE_T index);
CONST LATE_LOAD_ENTRY& FUNCTION vec_at(CONST VECTOR& vec, SIZE_T index);
SIZE_T FUNCTION vec_size(CONST VECTOR& vec);
BOOL FUNCTION vec_empty(CONST VECTOR& vec);
VOID FUNCTION pop_back(VECTOR& vec);
VOID FUNCTION vec_clear(VECTOR& vec);
VOID FUNCTION free_vector(VECTOR& vec);
