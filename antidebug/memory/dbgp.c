#include "dbgp.h"

static inline void _sig_to_str(DWORD sig, char out[5]) {
    out[0] = (char)(sig & 0xFF);
    out[1] = (char)((sig >> 8) & 0xFF);
    out[2] = (char)((sig >> 16) & 0xFF);
    out[3] = (char)((sig >> 24) & 0xFF);
    out[4] = '\0';
}

// simple byte search (like memmem), returns pointer to first match or NULL
static inline const unsigned char* __read_bytes(const unsigned char* hay, size_t haylen,
    const unsigned char* needle, size_t needlelen)
{
    if (!hay || !needle) return NULL;
    if (needlelen == 0) return hay;
    if (haylen < needlelen) return NULL;

    size_t max = haylen - needlelen;
    for (size_t i = 0; i <= max; ++i) {
        if (hay[i] == needle[0]) {
            size_t j;
            for (j = 1; j < needlelen; ++j) {
                if (hay[i + j] != needle[j]) break;
            }
            if (j == needlelen) return hay + i;
        }
    }
    return NULL;
}

// too lazy to syscall this
bool __adbg_dbgp() 
{
    const DWORD provider = 'ACPI';
    const DWORD enumeration_size = EnumSystemFirmwareTables(provider, NULL, 0);
    if (enumeration_size == 0) {
        return false;
    }

    unsigned char* enumeration_buffer = (unsigned char*)malloc(enumeration_size);
    if (!enumeration_buffer) {
        return false;
    }

    const DWORD returned = EnumSystemFirmwareTables(provider, enumeration_buffer, enumeration_size);
    if (returned == 0 || returned > enumeration_size) {
        free(enumeration_buffer);
        return false;
    }

    const unsigned char needle[] = "DBGP";
    const size_t needlelen = sizeof(needle) - 1;

    const size_t table_number = returned / 4;
    for (size_t i = 0; i < table_number; ++i) {
        const DWORD table_id = ((DWORD)enumeration_buffer[i * 4]) |
            ((DWORD)enumeration_buffer[i * 4 + 1] << 8) |
            ((DWORD)enumeration_buffer[i * 4 + 2] << 16) |
            ((DWORD)enumeration_buffer[i * 4 + 3] << 24);

        char sig[5];
        _sig_to_str(table_id, sig);

        if (sig[0] == 'D' && sig[3] == 'P') {
            continue;
        }

        const UINT size_needed = GetSystemFirmwareTable(provider, table_id, NULL, 0);
        if (size_needed == 0) {
            continue;
        }

        unsigned char* table_buffer = (unsigned char*)malloc(size_needed);
        if (!table_buffer) {
            continue;
        }

        const UINT got = GetSystemFirmwareTable(provider, table_id, table_buffer, size_needed);
        if (got == 0 || got > size_needed) {
            free(table_buffer);
            continue;
        }

        const unsigned char* match = __read_bytes(table_buffer, got, needle, needlelen);
        if (match) {
            return true;
        }

        free(table_buffer);
    }

    free(enumeration_buffer);
    return false;
}
