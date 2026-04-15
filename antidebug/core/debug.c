#include "debug.h"

static inline void AdbgWriteConsoleA(const char* text)
{
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written = 0;
    DWORD len = (DWORD)strlen(text);

    if (h != NULL && h != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode)) {
            WriteConsoleA(h, text, len, &written, NULL);
            return;
        }
        WriteFile(h, text, len, &written, NULL);
        return;
    }

    fputs(text, stderr);
    fflush(stderr);
}

void AdbgLogA(_Printf_format_string_ const char* fmt, ...)
{
    char buffer[2048];

    va_list args;
    va_start(args, fmt);
    if (vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, fmt, args) < 0) {
        strcpy_s(buffer, sizeof(buffer), "[adbg] log formatting failed");
    }
    va_end(args);

    size_t len = strnlen_s(buffer, sizeof(buffer));
    if (len == 0 || buffer[len - 1] != '\n') {
        strcat_s(buffer, sizeof(buffer), "\r\n");
    }

    OutputDebugStringA(buffer);
    AdbgWriteConsoleA(buffer);
}

void AdbgLogLastErrorA(_Printf_format_string_ const char* context)
{
    DWORD err = GetLastError();
    char sysMsg[512] = { 0 };

    DWORD chars = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        0,
        sysMsg,
        sizeof(sysMsg),
        NULL);

    if (chars == 0) {
        AdbgLogA("%s failed. GLE=%lu", context, (unsigned long)err);
        return;
    }

    while (chars > 0) {
        char c = sysMsg[chars - 1];
        if (c == '\r' || c == '\n' || c == ' ') {
            sysMsg[--chars] = '\0';
        }
        else {
            break;
        }
    }

    AdbgLogA("%s failed. GLE=%lu (%s)", context, (unsigned long)err, sysMsg);
}