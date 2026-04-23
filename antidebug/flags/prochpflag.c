#include "prochpflag.h"

static inline PUINT32 __readheap()
{
    PINT64 process_heap = NULL;
    PUINT32 heap_flags = NULL;

    process_heap = (PINT64)(__readgsqword(0x60) + 0x30);
    heap_flags = (PUINT32)(*(PINT64)process_heap + 0x70);

    return heap_flags;
}

bool __adbg_heap_flag()
{
    PUINT32 heap_flags = NULL;

    heap_flags = __readheap();

    if (heap_flags != NULL && *heap_flags > 2) {
        return true;
    }
    else {
        return false;
    }
}