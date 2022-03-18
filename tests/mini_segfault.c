#include <stdio.h>

int main()
{
    char* die;
    int killer = 420;
    while (1) {
       printf("%d", *(int*)(die) * killer);
       killer = killer * killer;
    }
    return 0;
}
