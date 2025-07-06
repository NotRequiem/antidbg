#include "window.h"

BOOL CALLBACK EnumWndProc(HWND hwnd, LPARAM lParam)
{
	char cur_window[1024];
	GetWindowTextA(hwnd, cur_window, 1023);
	if (strstr(cur_window, "WinDbg") != NULL || strstr(cur_window, "x64_dbg") != NULL || strstr(cur_window, "OllyICE") != NULL || strstr(cur_window, "OllyDBG") != NULL || strstr(cur_window, "Immunity") != NULL)
	{
		*((BOOL*)lParam) = TRUE;
	}
	return TRUE;
}

bool CheckWindow() {
	BOOL ret = FALSE;
	EnumWindows(EnumWndProc, (LPARAM)&ret);

	if (FindWindowA("OLLYDBG", NULL) != NULL || FindWindowA("WinDbgFrameClass", NULL) != NULL || FindWindowA("QWidget", NULL) != NULL)
	{
		return TRUE;
	}

	char fore_window[1024];
	GetWindowTextA(GetForegroundWindow(), fore_window, 1023);
	if (strstr(fore_window, "WinDbg") != NULL || strstr(fore_window, "x64_dbg") != NULL || strstr(fore_window, "OllyICE") != NULL || strstr(fore_window, "OllyDBG") != NULL || strstr(fore_window, "Immunity") != NULL)
	{
		return TRUE;
	}

	return ret;
}