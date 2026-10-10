#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC 0xBEEF

/*
 * Custom packet format:
 *
 * [0-1]  Magic      : 0xBE 0xEF
 * [2]    Version    : 1 or 2
 * [3]    Length     : payload length
 * [4]    Flags
 * [5...] Payload
 */

void process_packet(const uint8_t *data, size_t size)
{
    if (size < 5)
        return;

    uint16_t magic = ((uint16_t)data[0] << 8) | data[1];   // <<8 moves the first byte to the left, | is bitwise OR with the second byte

    if (magic != MAGIC)
        return;

    uint8_t version = data[2];

    if (version != 1 && version != 2)
        return;

    uint8_t payload_len = data[3];

    if (payload_len == 0)
        return;

    if (payload_len > 200)
        return;

    uint8_t flags = data[4];

    if (flags & 0x01)
        printf("DEBUG mode enabled\n");

    if (flags & 0x02)
        printf("Compression enabled\n");


    //Special command hidden deeper in the parser.

    if (version == 2 &&
        (flags & 0x04) &&
        payload_len >= 4 &&
        memcmp(data + 5, "EXEC", 4) == 0)
    {
        printf("Special command detected\n");
    }

    /*
     *  VULNERABILITY
     * The destination is only 32 bytes,
     * but payload_len can be much larger.
     */

    char payload[32];

    memcpy(payload, data + 5, payload_len);

    payload[31] = '\0';

    printf("Payload: %s\n", payload);
}
