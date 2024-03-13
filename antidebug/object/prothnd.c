#include "prothnd.h"

bool ProtectedHandle()
{
	HANDLE hMutex;

	// hMutex = CreateMutex(NULL, FALSE, _T("test"));
	hMutex = CreateMutexA(NULL, FALSE, "test");

	if (hMutex) {

		SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);


		__try {
			CloseHandle(hMutex);
		}

		__except (EXCEPTION_EXECUTE_HANDLER) {
			return TRUE;
		}

	}

	return FALSE;

}
