#include "link_test.hpp"
//__text(F) uint8_t data[8] = { 0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41};

//__text(B) int func_a() {
//    return 2*2;
//}
//
//__text(B) int func_b() {
//    return 1+1;
//}

__text(B) int Entrypoint() {
    //func_b();
    //func_a();
    return 0;
}
