crypt: crypt.c
	$(CC) -o crypt -std=c99 -lcrypt crypt.c

clean: distclean
distclean:
	rm -f crypt
