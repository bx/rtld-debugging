#include <unistd.h>
#include <stdlib.h>

const char *cmd = "/bin/bash";

int main(int argc, char *argv[])
{
    return execl(cmd, NULL);
}
