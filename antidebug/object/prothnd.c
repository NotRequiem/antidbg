#include "prothnd.h"
#include "..\core\syscall.h"

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION {
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION;

bool __adbg_protected_handle()
{
    HANDLE mutex_handle = CreateMutexA(NULL, FALSE, "a");

    if (mutex_handle) {
        OBJECT_HANDLE_FLAG_INFORMATION flag = { FALSE, TRUE };
        DbgNtSetInformationObject(mutex_handle, ObjectHandleFlagInformation, &flag, sizeof(flag));

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
        flag.ProtectFromClose = FALSE;
        ULONG flags = 0;
        DbgNtSetInformationObject(mutex_handle, ObjectHandleFlagInformation, &flags, sizeof(ULONG));
        DbgNtClose(mutex_handle);
    #pragma warning (default: 6001)
    }

    return false;
}