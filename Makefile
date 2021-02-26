CC=gcc
CFLAGS=-Wall -static-libgcc
LIBS=-lssh

ssh-honeypot: src/ssh-honeypot.c src/config.h
	$(CC) $(CFLAGS) -o ssh-honeypot src/ssh-honeypot.c $(LIBS)

clean:
	rm ssh-honeypot
