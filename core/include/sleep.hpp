#ifndef SLEEP_HPP
#define SLEEP_HPP

BOOL
FUNCTION
    AddValidCallTarget(VOID *pointer);

BOOL
FUNCTION
    ObfuscateSleep(PCONTEXT fake_frame, PLARGE_INTEGER Timeout);

#endif //SLEEP_HPP
