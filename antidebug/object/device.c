#include "device.h"
#include "..\core\syscall.h"

static bool IsDeviceObjectPresent(const wchar_t* pwszDeviceName)
{
    UNICODE_STRING device_name = { 0 };
    device_name.Length = (USHORT)(wcslen(pwszDeviceName) * sizeof(wchar_t));
    device_name.MaximumLength = device_name.Length + sizeof(wchar_t);
    device_name.Buffer = (PWSTR)pwszDeviceName;

    OBJECT_ATTRIBUTES object_attributes = { 0 };
    object_attributes.Length = sizeof(OBJECT_ATTRIBUTES);
    object_attributes.RootDirectory = NULL;
    object_attributes.ObjectName = &device_name;
    object_attributes.Attributes = OBJ_CASE_INSENSITIVE;
    object_attributes.SecurityDescriptor = NULL;
    object_attributes.SecurityQualityOfService = NULL;

    IO_STATUS_BLOCK io_status = { 0 };
    HANDLE devide_handle = NULL;

    const NTSTATUS status = DbgNtOpenFile(
        &devide_handle,
        FILE_READ_ATTRIBUTES,
        &object_attributes,
        &io_status,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0
    );

    if (NT_SUCCESS(status))
    {
        DbgNtClose(devide_handle);
        return true;
    }

    // if it exists but the driver developer secured it with an ACL preventing user-mode access
    if (status == STATUS_ACCESS_DENIED)
    {
        return true;
    }

    if (status != STATUS_OBJECT_NAME_NOT_FOUND && status != STATUS_OBJECT_PATH_NOT_FOUND)
    {
        // any other error (like STATUS_SHARING_VIOLATION) implies the object exists
        return true;
    }

    return false;
}

bool __adbg_device()
{
    bool debugged = false;

    if (IsDeviceObjectPresent(L"\\Device\\TitanHide"))
    {
        debugged = true;
    }

    if (IsDeviceObjectPresent(L"\\??\\TitanHide"))
    {
        debugged = true;
    }

    return debugged;
}