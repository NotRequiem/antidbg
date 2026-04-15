#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

	#ifdef _DEBUG

		void AdbgLogA(_Printf_format_string_ const char* fmt, ...);
		void AdbgLogLastErrorA(_Printf_format_string_ const char* context);

	#else

		#define AdbgLogA(...) ((void)0)
		#define AdbgLogLastErrorA(...) ((void)0)

	#endif

#ifdef __cplusplus
}
#endif
