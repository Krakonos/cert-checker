CFLAGS=-Wall -pedantic --std=c99 -lgnutls


all:	cert-checker test

cert-checker: main.o
	gcc $(CFLAGS) -o $@ $^

depend:
	gcc $(CFLAGS) -MM *.c > Makefile.depend

-include: Makefile.depend

test:
	./cert-checker localhost:5556

.PHONY: clean

clean:
	rm -f cert-checker *.o
