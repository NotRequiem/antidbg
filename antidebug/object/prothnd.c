#include "prothnd.h"
#include "..\core\syscall.h"

bool ProtectedHandle()
{
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "a");
    if (hMutex) {
        ULONG flag = HANDLE_FLAG_PROTECT_FROM_CLOSE;
        DbgNtSetInformationObject(hMutex, ObjectHandleFlagInformation, &flag, sizeof(ULONG));

        __try {
            CloseHandle(hMutex);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ULONG flags = 0;
            DbgNtSetInformationObject(hMutex, ObjectHandleFlagInformation, &flags, sizeof(ULONG));
            DbgNtClose(hMutex);
            return TRUE;
        }

#pragma warning (disable: 6001)
        ULONG flags = 0;
        DbgNtSetInformationObject(hMutex, ObjectHandleFlagInformation, &flags, sizeof(ULONG));
        DbgNtClose(hMutex);
#pragma warning (default: 6001)
    }
    return FALSE;
}
