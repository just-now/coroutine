all:
	gcc -std=c99 -o test -g3 -O0 coroutine.* test.c
clean:
	rm -f test
