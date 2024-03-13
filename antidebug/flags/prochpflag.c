#include "prochpflag.h"

#if defined (ENV64BIT)
PUINT32 GetHeapFlags_x64()
{
	PINT64 pProcessHeap = NULL;
	PUINT32 pHeapFlags = NULL;
	if (IsWindowsVistaOrGreater()) {
		pProcessHeap = (PINT64)(__readgsqword(0x60) + 0x30);
		pHeapFlags = (PUINT32)(*pProcessHeap + 0x70);
	}

	else {
		pProcessHeap = (PINT64)(__readgsqword(0x60) + 0x30);
		pHeapFlags = (PUINT32)(*pProcessHeap + 0x14);
	}

	return pHeapFlags;
}

#elif defined(ENV32BIT)
PUINT32 GetHeapFlags_x86()
{
	PUINT32 pProcessHeap, pHeapFlags = NULL;

	if (IsWindowsVistaOrGreater()) {
		pProcessHeap = (PUINT32)(__readfsdword(0x30) + 0x18);
		pHeapFlags = (PUINT32)(*pProcessHeap + 0x40);
	}

	else {
		pProcessHeap = (PUINT32)(__readfsdword(0x30) + 0x18);
		pHeapFlags = (PUINT32)(*pProcessHeap + 0x0C);
	}

	return pHeapFlags;
}
#endif


bool ProcessHeapFlag()
{
	PUINT32 pHeapFlags = NULL;

#if defined (ENV64BIT)
	pHeapFlags = GetHeapFlags_x64();

#elif defined(ENV32BIT)
	pHeapFlags = GetHeapFlags_x86();

#endif

	if (*pHeapFlags > 2)
		return TRUE;
	else
		return FALSE;
}
