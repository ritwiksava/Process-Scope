// raw_syscall.c
#include <unistd.h>

int main(void) {
    const char msg[] = "HELLO\n";

    long ret;

    asm volatile(
        "mov $1, %%rax\n"
        "mov $1, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov $6, %%rdx\n"
        "syscall\n"
        "mov %%rax, %0\n"
        : "=r"(ret)
        : "r"(msg)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );

    return ret < 0;
}
