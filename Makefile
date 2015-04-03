crypt: crypt.c
	$(CC) -o crypt -std=c99 -lcrypt crypt.c

install:
	install crypt /usr/bin
	gzip -c ./man/crypt.1 > /usr/share/man/man1/crypt.1.gz

clean: distclean
distclean:
	rm -f crypt
