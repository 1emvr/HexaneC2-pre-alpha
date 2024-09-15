#ifndef SLEEP_HPP
#define SLEEP_HPP

FUNCTION BOOL AddValidCallTarget(void* pointer);
FUNCTION BOOL ObfuscateSleep(PCONTEXT fake_frame, PLARGE_INTEGER Timeout);

#endif //SLEEP_HPP
