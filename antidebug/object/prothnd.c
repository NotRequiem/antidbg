#include "prothnd.h"
#include "..\core\syscall.h"

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION {
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION;

bool __adbg_protected_handle()
{
    HANDLE mutex_handle = CreateMutexA(NULL, FALSE, NULL);

    if (mutex_handle) {
        OBJECT_HANDLE_FLAG_INFORMATION flag = { FALSE, TRUE };
        DbgNtSetInformationObject(mutex_handle, ObjectHandleFlagInformation, &flag, sizeof(flag));

        bool was_closed = false;
        bool debugged = false;

        __try {
            if (CloseHandle(mutex_handle)) {
                was_closed = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            debugged = true;
        }

        if (!was_closed) {
            flag.ProtectFromClose = FALSE;
            DbgNtSetInformationObject(mutex_handle, ObjectHandleFlagInformation, &flag, sizeof(flag));
            DbgNtClose(mutex_handle);
        }
        else {
            debugged = true;
        }

        return debugged;
    }

    return false;
}