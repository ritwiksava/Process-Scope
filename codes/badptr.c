#include <unistd.h>

int main(void) {
    char *bad = (char *)0x12345678;

    write(1, bad, 10);

    return 0;
}
