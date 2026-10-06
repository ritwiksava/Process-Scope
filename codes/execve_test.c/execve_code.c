// exec_test.c
#include <unistd.h>
#include <stdio.h>

int main(void) {
    char *args[] = {"/bin/echo", "HELLO", NULL};

    printf("Before execve\n");

    execve("/bin/echo", args, NULL);

    perror("execve");
    return 1;
}
