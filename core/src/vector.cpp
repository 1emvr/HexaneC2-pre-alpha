#include <iostream>
#include <stdlib.hpp>

// Define the structure for our vector
template <typename T>
struct SimpleVector {
    T* data;           // Pointer to the dynamically allocated array
    size_t capacity;   // Current capacity of the array
    size_t length;     // Number of elements in the array
};

// Initialize the vector
template <typename T>
void init_vector(SimpleVector<T>& vec) {
    vec.data = nullptr;
    vec.capacity = 0;
    vec.length = 0;
}

template <typename T>
void push_back(SimpleVector<T>& vec, const T& value) {
	HEXANE;

    if (vec.length == vec.capacity) {
        size_t new_capacity = (vec.capacity == 0) ? 1 : vec.capacity * 2;
        T* new_data = (T*) Malloc(new_capacity);

        if (vec.data) {
            MemCopy(new_data, vec.data, vec.length * sizeof(T));
            Free(vec.data);
        }

        vec.data = new_data;
        vec.capacity = new_capacity;
    }

    vec.data[vec.length] = value;
    ++vec.length;
}

template <typename T>
T& at(SimpleVector<T>& vec, size_t index) {
    if (index >= vec.length) {
        /* throw std::out_of_range("Index out of range"); */
    }
    return vec.data[index];
}

template <typename T>
const T& at(const SimpleVector<T>& vec, size_t index) {
    if (index >= vec.length) {
        /* throw std::out_of_range("Index out of range"); */
    }
    return vec.data[index];
}

// Return the current number of elements
template <typename T>
size_t size(const SimpleVector<T>& vec) {
    return vec.length;
}

// Return true if the vector is empty
template <typename T>
bool empty(const SimpleVector<T>& vec) {
    return vec.length == 0;
}

// Remove the last element
template <typename T>
void pop_back(SimpleVector<T>& vec) {
    if (vec.length > 0) {
        --vec.length;
    }
}

// Clear all elements
template <typename T>
void clear(SimpleVector<T>& vec) {
    vec.length = 0;
}

// Destructor-like function to free the memory
template <typename T>
void free_vector(SimpleVector<T>& vec) {
    if (vec.data) {
        delete[] vec.data;
    }
}
