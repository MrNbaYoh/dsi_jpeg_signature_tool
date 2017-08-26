CFLAGS=-Wall -Wextra -pedantic -std=gnu99
CC=gcc

all: sign
sign: dsi.o aes.o main.o
	$(CC) dsi.o aes.o main.o -o sign

dsi.o: dsi.c
	$(CC) -c dsi.c $(CFLAGS)

aes.o: aes.c
	$(CC) -c aes.c $(CFLAGS)

main.o: main.c
	$(CC) -c main.c $(CFLAGS)

clean:
	rm aes.o dsi.o main.o sign
