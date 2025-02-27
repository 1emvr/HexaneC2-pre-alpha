#include <core/include/vector.hpp>

VOID FUNCTION init_vector(VECTOR& vec) {
    vec.data = nullptr;
    vec.capacity = 0;
    vec.length = 0;
}

VOID FUNCTION push_back(VECTOR& vec, CONST LATE_LOAD_ENTRY& value) {
	HEXANE;

    if (vec.length == vec.capacity) {
        SIZE_T new_capacity = (vec.capacity == 0) ? 1 : vec.capacity * 2;
        LATE_LOAD_ENTRY* new_data = (LATE_LOAD_ENTRY*) Malloc(new_capacity);

        if (vec.data) {
            MemCopy((VOID*)new_data, (VOID*)vec.data, vec.length * sizeof(LATE_LOAD_ENTRY));
            Free((VOID*)vec.data);
        }

        vec.data = new_data;
        vec.capacity = new_capacity;
    }

    vec.data[vec.length] = value;
    ++vec.length;
}

LATE_LOAD_ENTRY& FUNCTION vec_at(VECTOR& vec, SIZE_T index) {
    if (index >= vec.length) {
        /* throw std::out_of_range("Index out of range"); */
    }
    return vec.data[index];
}

CONST LATE_LOAD_ENTRY& FUNCTION vec_at(CONST VECTOR& vec, SIZE_T index) {
    if (index >= vec.length) {
        /* throw std::out_of_range("Index out of range"); */
    }
    return vec.data[index];
}

SIZE_T FUNCTION vec_size(CONST VECTOR& vec) {
    return vec.length;
}

BOOL FUNCTION vec_empty(CONST VECTOR& vec) {
    return vec.length == 0;
}

VOID FUNCTION pop_back(VECTOR& vec) {
    if (vec.length > 0) {
        --vec.length;
    }
}

VOID FUNCTION vec_clear(VECTOR& vec) {
    vec.length = 0;
}

VOID FUNCTION free_vector(VECTOR& vec) {
	HEXANE;
    if (vec.data) {
        Free((void*)vec.data);
    }
}
