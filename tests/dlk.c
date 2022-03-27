#include <pthread.h>
#include <stdio.h>

static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;


int bar()
{
	pthread_mutex_lock(&mut);
	printf("PWET!\n");
}

int foo()
{
	pthread_mutex_lock(&mut);
	bar();
}

int main( int argc, char ** argv)
{
	foo();

	return 0;
}
