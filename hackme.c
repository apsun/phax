#include <stdio.h>
#include <string.h>
#include <stdlib.h>

volatile int foo = 0;

int
main(void)
{
    while (1) {
        printf("read | write <value>: ");
        char buf[256];
        fgets(buf, sizeof(buf), stdin);
        if (strncmp(buf, "read", strlen("read")) == 0) {
            printf("%d\n", foo);
        } else if (strncmp(buf, "write ", strlen("write ")) == 0) {
            foo = strtol(&buf[strlen("write ")], NULL, 0);
        }
    }
}
