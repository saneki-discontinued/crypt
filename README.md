crypt - hash passwords with crypt(3)
------------------------------------

Easily hash passwords using libcrypt, resulting in hashes of
the same format as seen in `/etc/shadow`.

To build, just `make`.

Example: `crypt -s "someSalt" "myPassword"`
