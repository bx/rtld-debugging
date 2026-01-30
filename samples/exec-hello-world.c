#include <unistd.h>
#include <stdlib.h>

const char *cmd = "./hello-world";
int main(int argc, char *argv[])
{
    return execl(cmd, NULL);
}
