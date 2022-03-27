#include <stdio.h>


void foo(int n)
{
	char st[1];

	if(n>8)
	{
		int i;
		for(i = 0; i <128; i++)
		{
			st[i] = '\0';
		}

		return;
	}

	foo(n+1);
}


int main( int argc, char ** argv)
{
	foo(0);

	return 0;
}
