#include "random.h"

// ASLR based entropy random generator without using APIs, or instructions a hypervisor can vmexit in, or kernel structures a driver can modify.

static _force_inline uint64_t __rotl64(uint64_t x, unsigned r)
{
    return (x << (r & 63)) | (x >> ((64 - r) & 63));
}

static _force_inline uint64_t _splitmix64_final(uint64_t x)
{
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

/*
static _force_inline uint64_t _splitmix64(uint64_t* state)
{
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}
*/

_no_inline static uint64_t _harvest_stack_shape(uint64_t salt)
{
    volatile uint64_t pad[8] = { 0 };

    for (int i = 0; i < 8; ++i)
    {
        pad[i] = (uint64_t)(uintptr_t)&pad[i] ^ (salt + (uint64_t)i * 0x9e3779b97f4a7c15ULL);
    }

    uint64_t x = salt;
    x ^= (uint64_t)(uintptr_t)&pad;
    x ^= __rotl64((uint64_t)(uintptr_t)&pad[0], 3);
    x ^= __rotl64((uint64_t)(uintptr_t)&pad[1], 11);
    x ^= __rotl64((uint64_t)(uintptr_t)&pad[2], 19);
    x ^= __rotl64((uint64_t)(uintptr_t)&pad[3], 27);
    x ^= __rotl64((uint64_t)(uintptr_t)&pad[4], 35);
    x ^= __rotl64((uint64_t)(uintptr_t)&pad[5], 43);
    x ^= __rotl64((uint64_t)(uintptr_t)&pad[6], 51);
    x ^= __rotl64((uint64_t)(uintptr_t)&pad[7], 59);

    x ^= (uint64_t)(uintptr_t)_AddressOfReturnAddress();
    x ^= (uint64_t)(uintptr_t)_ReturnAddress();
    x ^= (uint64_t)(uintptr_t)&_harvest_stack_shape;

    for (int i = 0; i < 8; ++i)
    {
        x ^= __rotl64(pad[i], (unsigned)(i * 7 + 1));
    }

    return _splitmix64_final(x);
}

_no_inline static uint64_t _harvest_call_chain(uint64_t seed, int depth)
{
    volatile uint64_t local = seed ^ (uint64_t)(uintptr_t)&seed ^ (uint64_t)(uintptr_t)&local;

    uint64_t x = seed;
    x ^= (uint64_t)(uintptr_t)&local;
    x ^= (uint64_t)(uintptr_t)&seed;
    x ^= (uint64_t)(uintptr_t)_AddressOfReturnAddress();
    x ^= (uint64_t)(uintptr_t)_ReturnAddress();
    x ^= (uint64_t)(uintptr_t)&_harvest_call_chain;

    x = _splitmix64_final(x + local);

    if (depth > 0)
    {
        x ^= __rotl64(_harvest_call_chain(x ^ 0xD1B54A32D192ED03ULL, depth - 1), (unsigned)(depth * 13));
    }

    x ^= _harvest_stack_shape(x ^ 0xA0761D6478BD642FULL);
    return _splitmix64_final(x);
}

static uint64_t _force_inline _entropy_gen(void)
{
    volatile uint64_t a = 0;
    volatile uint64_t b = 0;

    uint64_t x = 0;

    x ^= (uint64_t)(uintptr_t)&a;
    x ^= __rotl64((uint64_t)(uintptr_t)&b, 7);
    x ^= __rotl64((uint64_t)(uintptr_t)&x, 17);
    x ^= __rotl64((uint64_t)(uintptr_t)&_entropy_gen, 29);
    x ^= __rotl64((uint64_t)(uintptr_t)_AddressOfReturnAddress(), 41);
    x ^= __rotl64((uint64_t)(uintptr_t)_ReturnAddress(), 53);

    x ^= _harvest_call_chain(x ^ 0x9E3779B97F4A7C15ULL, 2);
    x ^= _harvest_stack_shape(x ^ 0xBF58476D1CE4E5B9ULL);

    return _splitmix64_final(x);
}

static volatile uint64_t _entropy_state = 0;
static volatile uint64_t _entropy_counter = 0;

static _force_inline uint64_t _entropy_next(void)
{
    uint64_t s = _entropy_state;

    if (s == 0)
    {
        s = _entropy_gen();
        s ^= (uint64_t)(uintptr_t)&_entropy_state;
        s ^= (uint64_t)(uintptr_t)&_entropy_counter;
        s ^= __rotl64((uint64_t)(uintptr_t)&s, 19);
        s = _splitmix64_final(s);

        if (s == 0)
        {
            s = 0xD1B54A32D192ED03ULL;
        }
    }

    // we must generate something different because the ASRL seed won't differ after the process is created
    s ^= ++_entropy_counter;
    s ^= __rotl64((uint64_t)(uintptr_t)&s, 7);
    s ^= _splitmix64_final(s + 0x9E3779B97F4A7C15ULL);
    s = _splitmix64_final(s);

    if (s == 0)
    {
        s = 0xA0761D6478BD642FULL ^ _entropy_counter;
    }

    _entropy_state = s;
    return s;
}

uint64_t __randomize(uint64_t min, uint64_t max)
{
    if (min > max) {
        uint64_t tmp = min;
        min = max;
        max = tmp;
    }

    uint64_t range = max - min + 1;
    if (range == 0) {
        return _entropy_next(); // full 64-bit span case
    }

    uint64_t x = _entropy_next();
    uint64_t limit = UINT64_MAX - (UINT64_MAX % range);

    while (x >= limit) {
        x = _entropy_next();
    }

    return min + (x % range);
}