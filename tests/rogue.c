#include <stdio.h>

static int large[1024];


int main( int argc, char ** argv)
{
	unsigned long int i;

	do
	{
		large[i] = 0xdeadbeef;
	}while(++i);

	printf("%d\n", i);

	return 0;
}
