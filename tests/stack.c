int foo();

int bar()
{
	foo();
}

int foo()
{
	bar();
}

int main( int argc, char ** argv)
{
	foo();

	return 0;
}
