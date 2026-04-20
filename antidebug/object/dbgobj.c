#include "dbgobj.h"
#include "..\core\syscall.h"

bool __adbg_query_object()
{
    bool debugged = false;
    HANDLE debug_object = NULL;
    OBJECT_ATTRIBUTES object_attributes = { 0 };

    InitializeObjectAttributes(&object_attributes, NULL, 0, NULL, NULL);

    // if a debugger is hiding itself, it might hook this or the subsequent query to spoof object counts
    NTSTATUS status = DbgNtCreateDebugObject(&debug_object, DEBUG_ALL_ACCESS, &object_attributes, FALSE);
    if (!NT_SUCCESS(status)) {
        return false;
    }

    ULONG required_length = 0;

    // query required buffer size
    status = DbgNtQueryObject(debug_object, ObjectTypeInformation, NULL, 0, &required_length);

    if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW) {

        POBJECT_TYPE_INFORMATION type_info = (POBJECT_TYPE_INFORMATION)malloc(required_length);

        if (type_info != NULL) {

            // query actual object information
            status = DbgNtQueryObject(debug_object, ObjectTypeInformation, type_info, required_length, NULL);

            if (NT_SUCCESS(status)) {

                // since we just created a debug object, the count MUST be > 0. If it is 0, something is spoofing the results
                if (type_info->TotalNumberOfHandles == 0 || type_info->TotalNumberOfObjects == 0) {
                    debugged = true;
                }

                // detect handle stripping
                status = DbgNtQueryObject(debug_object, ObjectTypeInformation, type_info, required_length, (PULONG)&type_info->TypeName.Buffer);

                if (status == STATUS_ACCESS_VIOLATION) {
                    debugged = true;
                }
            }

            free(type_info);
        }
    }

    DbgNtClose(debug_object);

    return debugged;
}