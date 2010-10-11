CFLAGS=-Wall -pedantic --std=c99 -lgnutls


all:	cert-checker

cert-checker: main.o
	gcc $(CFLAGS) -o $@ $^

depend:
	gcc $(CFLAGS) -MM *.c > Makefile.depend

-include: Makefile.depend

.PHONY: clean

clean:
	rm -f cert-checker *.o

install:
	install -o root -g root cert-checker /usr/local/bin
