#include <core/corelib.hpp>

template<typename T>
class Vec {
private:
    T* data;
    size_t capacity;
    size_t size;
    static T default_value;

    void grow() {
        HEXANE

        size_t new_cap  = capacity * 2;
        T* new_data     = (T*)x_malloc(new_cap * sizeof(T));

        if (!new_data) {
            ntstatus = ERROR_NOT_ENOUGH_MEMORY;
            return;
        }

        x_memcpy(new_data, data, size * sizeof(T));
        x_free(data);

        data        = new_data;
        capacity    = new_cap;
    }

public:
    Vec() : data(nullptr), capacity(0), size(0) {
        HEXANE

        capacity    = 4;
        data        = (T*)x_malloc(capacity * sizeof(T));

        if (!data) {
            ntstatus = ERROR_NOT_ENOUGH_MEMORY;
            return;
        }
    }

    ~Vec() {
        HEXANE
        if (data) { x_free(data); }
    }

    void push_back(const T& value) {
        if (size >= capacity) {
            grow();
        }
        data[size++] = value;
    }

    T& operator[](size_t index) {
        HEXANE

        if (index >= size) {
            ntstatus = ERROR_INVALID_INDEX;
            return default_value;
        }
        return data[index];
    }

    size_t get_size() const {
        return size;
    }

    size_t get_capacity() const {
        return capacity;
    }
};

class String {
private:
    char* data;
    size_t size;
    size_t capacity;


    void grow(size_t new_cap) {
        HEXANE

        char* new_data = (char*)x_malloc(new_cap);
        if (!new_data) {
            ntstatus = ERROR_NOT_ENOUGH_MEMORY;
            return;
        }

        x_strcpy(new_data, data);
        x_free(data);

        data = new_data;
        capacity = new_cap;
    }

public:
    String() : data(nullptr), size(0), capacity(0) {
        HEXANE

        capacity    = 16;
        data        = (char*)x_malloc(capacity);

        if (!data) {
            ntstatus = ERROR_NOT_ENOUGH_MEMORY;
            return;
        }
        data[0] = '\0';
    }

    String(const char* str) : data(nullptr), size(0), capacity(0) {
        HEXANE

        size        = x_strlen(str);
        capacity    = size + 1;

        data = (char*)x_malloc(capacity);
        if (!data) {
            ntstatus = ERROR_NOT_ENOUGH_MEMORY;
            return;
        }

        x_strcpy(data, str);
    }

    ~String() {
        HEXANE
        if (data) { x_free(data); }
    }

    size_t length() const {
        return size;
    }

    const char* c_str() const {
        return data;
    }

    void append(const char* str) {
        size_t append_size = x_strlen(str);

        if (size + append_size + 1 > capacity) {
            grow((size + append_size + 1) * 2);
        }

        x_strcpy(data + size, str);
        size += append_size;
    }

    char& operator[](size_t index) {
        HEXANE

        if (index >= size) {
            ntstatus = ERROR_INVALID_INDEX;
            static char dummy = '\0';
            return dummy;
        }

        return data[index];
    }

    String& operator=(const char* str) {
        size_t new_size = strlen(str);

        if (new_size + 1 > capacity) {
            grow(new_size + 1);
        }
        x_strcpy(data, str);
        size = new_size;

        return *this;
    }

    String(const String& other) : data(nullptr), size(0), capacity(0) {
        HEXANE

        size        = other.size;
        capacity    = other.capacity;

        data = (char*)x_malloc(capacity);
        if (!data) {
            ntstatus = ERROR_NOT_ENOUGH_MEMORY;
            return;
        }

        x_strcpy(data, other.data);
    }

    String& operator=(const String& other) {
        if (this != &other) {
            if (other.size + 1 > capacity) {
                grow(other.size + 1);
            }

            x_strcpy(data, other.data);
            size = other.size;
        }
        return *this;
    }
};

template<typename K, typename V>
class unordered_map {
private:
    struct Node {
        K key;
        V value;
        Node* next;
    };

    Node** table;
    size_t capacity;
    size_t size;

    void* heap;

    uint32_t hash(const K& key) const {

        // todo: this will not work
        const char* k = reinterpret_cast<const char*>(&key);
        return Utils::GetHashFromStringA(k, x_strlen(k));
    }

    void resize() {
        HEXANE

        size_t new_cap = capacity * 2;
        Node** new_table = (Node**)x_malloc(new_cap * sizeof(Node*));

        if (!new_table) {
            ntstatus = ERROR_NOT_ENOUGH_MEMORY;
            return;
        }

        x_memset(new_table, 0, new_cap * sizeof(Node*));

        for (size_t i = 0; i < capacity; ++i) {
            Node* node = table[i];

            while (node) {
                Node* next      = node->next;
                size_t newIndex = hash(node->key) % new_cap;

                node->next          = new_table[newIndex];
                new_table[newIndex] = node;
                node                = next;
            }
        }

        x_free(table);

        table = new_table;
        capacity = new_cap;
    }

public:
    unordered_map() : capacity(16), size(0) {
        HEXANE

        table = (Node**)x_malloc(capacity * sizeof(Node*));
        if (!table) {
            ntstatus = ERROR_NOT_ENOUGH_MEMORY;
            return;
        }

        x_memset(table, 0, capacity * sizeof(Node*));
    }

    ~unordered_map() {
        HEXANE

        for (size_t i = 0; i < capacity; ++i) {
            Node* node = table[i];

            while (node) {
                Node* next = node->next;
                x_free(node);
                node = next;
            }
        }

        x_free(table);
    }

    void insert(const K& key, const V& value) {
        HEXANE

        if (size >= capacity) {
            resize();
        }

        size_t index = hash(key);
        Node* node = table[index];

        while (node) {
            if (node->key == key) {
                node->value = value;
                return;
            }
            node = node->next;
        }

        node = (Node*)x_malloc(sizeof(Node));
        if (!node) {
            ntstatus = ERROR_NOT_ENOUGH_MEMORY;
            return;
        }

        node->key       = key;
        node->value     = value;
        node->next      = table[index];
        table[index]    = node;

        ++size;
    }

    bool find(const K& key, V& value) const {
        size_t index = hash(key);

        Node* node = table[index];
        while (node) {
            if (node->key == key) {
                value = node->value;
                return true;
            }
            node = node->next;
        }
        return false;
    }

    bool erase(const K& key) {
        HEXANE
        size_t index = hash(key);

        Node* node = table[index];
        Node* prev = nullptr;
        while (node) {
            if (node->key == key) {
                if (prev) {
                    prev->next = node->next;
                } else {
                    table[index] = node->next;
                }
                x_free(node);
                --size;
                return true;
            }
            prev = node;
            node = node->next;
        }
        return false;
    }

    size_t get_size() const {
        return size;
    }

    bool is_empty() const {
        return size == 0;
    }
};

int main() {
    unordered_map<int, std::string> map;
    map.insert(1, "one");
    map.insert(2, "two");
    map.insert(3, "three");

    String value;
    if (map.find(2, value)) {
        std::cout << "Found: " << value << std::endl;
    } else {
        std::cout << "Not found" << std::endl;
    }

    map.erase(2);
    if (map.find(2, value)) {
        std::cout << "Found: " << value << std::endl;
    } else {
        std::cout << "Not found" << std::endl;
    }

    return 0;
}
