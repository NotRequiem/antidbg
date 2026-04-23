#pragma once

#include <stdint.h>
#include <intrin.h>

#if defined(__clang__) || defined(__GNUC__)
    #define _force_inline __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
    #define _force_inline __forceinline
#else
    #define _force_inline inline
#endif

#if defined(__clang__) || defined(__GNUC__)
    #define _no_inline __attribute__((noinline))
#elif defined(_MSC_VER)
    #define _no_inline __declspec(noinline)
#else
    #define _no_inline
#endif

#ifdef __cplusplus
extern "C" {
#endif

    uint64_t __randomize(uint64_t min, uint64_t max);

#ifdef __cplusplus
}
#endif