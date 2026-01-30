#include <string.h>
#include <stdio.h>
#include <unistd.h>

char *allowed = "/bin/ls";

int main(int argc, char *argv[])
{
    if (argc == 2) {
        if (strcmp(argv[1], allowed) == 0) {
            execl(allowed, NULL);
        } else {
            printf("The following command cannot be executed: ");
            printf(argv[1], 0);
        }
    }
    return 0;
}
