#include <stdio.h>

char hw[] = {'h', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '!', '\n', 0}; //"hello, world\n
char *notused = "hello, relocs\n";

int main(int argc, char *argv[])
{
    printf(hw);
    return 0;
}
