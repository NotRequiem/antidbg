#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

	#if defined(_DEBUG)

		void __log(_Printf_format_string_ const char* fmt, ...);
		void __log_error(_Printf_format_string_ const char* context);

	#else

		#define __log(...)       ((void)0)
		#define __log_error(...) ((void)0)

	#endif

#ifdef __cplusplus
}
#endif