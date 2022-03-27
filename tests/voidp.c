int bar()
{
	((void (*)())0x0)();
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
