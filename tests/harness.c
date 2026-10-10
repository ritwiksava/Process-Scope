#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

void process_packet(const uint8_t *data, size_t size);

int main(void)
{
    uint8_t buffer[4096];

    size_t size = fread(
        buffer,
        1,
        sizeof(buffer),
        stdin
    );

    process_packet(buffer, size);

    return 0;
}
