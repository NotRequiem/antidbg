#include "prochpflag.h"

static inline PUINT32 GetHeapFlags_x64()
{
    PINT64 pProcessHeap = NULL;
    PUINT32 pHeapFlags = NULL;

    pProcessHeap = (PINT64)(__readgsqword(0x60) + 0x30);
    pHeapFlags = (PUINT32)(*(PINT64)pProcessHeap + 0x70);

    return pHeapFlags;
}

bool ProcessHeapFlag()
{
    PUINT32 pHeapFlags = NULL;

    pHeapFlags = GetHeapFlags_x64();

    if (pHeapFlags != NULL && *pHeapFlags > 2) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}