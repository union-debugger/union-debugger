#include <stdlib.h>

int main( int argc, char ** argv)
{
	void * p = malloc(8);

	free(p);
	free(p);

	return 0;
}
