#include <stdio.h>

void callback(int d){
    printf("d: %d\n", d);
}

void foo(int d){
    callback(d);
}

int main() {
    foo(12);
    return 0;
}
