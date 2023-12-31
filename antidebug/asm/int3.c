#include "int3.h"

bool g_bDebugged = false;

static int filter(unsigned int code, struct _EXCEPTION_POINTERS* ep)
{
    g_bDebugged = code != EXCEPTION_BREAKPOINT;
    return EXCEPTION_EXECUTE_HANDLER;
}

bool int3()
{
    __try
    {
        __debugbreak();
    }
    __except (filter(GetExceptionCode(), GetExceptionInformation()))
    {
        return g_bDebugged;
    }
}