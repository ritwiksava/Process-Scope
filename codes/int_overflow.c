#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

struct packet {
    uint32_t count;
    uint32_t size;
    char *data;
};

void process(struct packet *p) {
    size_t total = p->count * p->size;

    char *buf = malloc(total);

    memcpy(buf, p->data, total);

    free(buf);
}

int main(void) {
    char data[1024];

    struct packet p = {
        .count = 100,
        .size = 10,
        .data = data
    };

    process(&p);
}
