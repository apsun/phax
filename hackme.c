#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#define BUF_SIZE 60000
typedef int32_t T;
volatile T mem[BUF_SIZE];

int
main(void)
{
    srand(time(NULL));
    volatile T *value = &mem[rand() % BUF_SIZE];

    while (1) {
        printf("read | write <value>: ");
        char buf[256];
        fgets(buf, sizeof(buf), stdin);
        if (strncmp(buf, "read", strlen("read")) == 0) {
            printf("%jd\n", (intmax_t)*value);
        } else if (strncmp(buf, "write ", strlen("write ")) == 0) {
            *value = strtoll(&buf[strlen("write ")], NULL, 0);
            for (int i = 0; i < BUF_SIZE / 20; ++i) {
                int off = rand() % sizeof(T);
                char *p = (char *)&mem[rand() % (BUF_SIZE - 1)];
                *(T *)(p + off) = *value;
            }
        }
    }
}
