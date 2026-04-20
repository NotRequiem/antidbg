#include "prothnd.h"
#include "..\core\syscall.h"

bool __adbg_protected_handle()
{
    HANDLE mutex_handle = CreateMutexA(NULL, FALSE, "a");
    if (mutex_handle) {
        ULONG flag = HANDLE_FLAG_PROTECT_FROM_CLOSE;
        DbgNtSetInformationObject(mutex_handle, ObjectHandleFlagInformation, &flag, sizeof(ULONG));

        __try {
            CloseHandle(mutex_handle);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ULONG flags = 0;
            DbgNtSetInformationObject(mutex_handle, ObjectHandleFlagInformation, &flags, sizeof(ULONG));
            DbgNtClose(mutex_handle);
            return true;
        }

    #pragma warning (disable: 6001)
        ULONG flags = 0;
        DbgNtSetInformationObject(mutex_handle, ObjectHandleFlagInformation, &flags, sizeof(ULONG));
        DbgNtClose(mutex_handle);
    #pragma warning (default: 6001)
    }
    return false;
}
