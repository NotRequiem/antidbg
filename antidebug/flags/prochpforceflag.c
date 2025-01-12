#include "prochpforceflag.h"

static inline PUINT32 GetForceFlags_x64() {
	PINT64 pProcessHeap = NULL;
	PUINT32 pHeapForceFlags = NULL;
	pProcessHeap = (PINT64)(__readgsqword(0x60) + 0x30);
	pHeapForceFlags = (PUINT32)(*pProcessHeap + 0x74);

	return pHeapForceFlags;
}

bool ProcessHeapForceFlag() {
	PUINT32 pHeapForceFlags = NULL;

	pHeapForceFlags = GetForceFlags_x64();

	if (*pHeapForceFlags > 0)
		return TRUE;
	else
		return FALSE;
}
