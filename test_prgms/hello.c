#include <stdio.h>

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("Not enought arguments\n");
    }
    printf("Hello %s!\n", argv[1]);
    return 0;
}
