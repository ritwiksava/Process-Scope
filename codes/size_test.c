#include <unistd.h>
#include <stdint.h>

int main(void) {
    char buf[16] = "HELLO";

    write(1, buf, 1000000000);

    return 0;
}
