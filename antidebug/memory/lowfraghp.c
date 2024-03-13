#include "lowfraghp.h"

bool LowFragmentationHeap()
{
	PINT_PTR FrontEndHeap = NULL;

	HANDLE hHeap = GetProcessHeap();

	if (IsWindowsVista() || IsWindows7()) {
#if defined (ENV64BIT)
		FrontEndHeap = (PINT_PTR)((CHAR*)hHeap + 0x178);

#elif defined(ENV32BIT)
		FrontEndHeap = (PINT_PTR)((CHAR*)hHeap + 0xd4);
#endif
	}

	if (IsWindows8or8PointOne()) {
#if defined (ENV64BIT)
		FrontEndHeap = (PINT_PTR)((CHAR*)hHeap + 0x170);

#elif defined(ENV32BIT)
		FrontEndHeap = (PINT_PTR)((CHAR*)hHeap + 0xd0);
#endif
	}

	if (FrontEndHeap && *FrontEndHeap == NULL) {
		return TRUE;
	}

	return FALSE;
}
