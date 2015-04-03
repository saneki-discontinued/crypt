crypt: crypt.c
	$(CC) -o crypt -std=c99 -lcrypt crypt.c

install:
	install crypt /usr/bin

clean: distclean
distclean:
	rm -f crypt
