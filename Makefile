CC := gcc
LDFLAGS := -o ssl-client -I/usr/include/SDL2 -D_REENTRANT -lSDL2 -lSDL2_mixer -lssl -lcrypto
UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
CFLAGS := -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
endif

all: ssl-client ssl-server

ssl-client: ssl-client.o
	$(CC) $(CFLAGS) -o ssl-client ssl-client.o $(LDFLAGS)

ssl-client.o: ssl-client.c
	$(CC) $(CFLAGS) -c ssl-client.c

ssl-server: ssl-server.o
	$(CC) $(CFLAGS) -o ssl-server ssl-server.o $(LDFLAGS)

ssl-server.o: ssl-server.c
	$(CC) $(CFLAGS) -c ssl-server.c

clean:
	rm -f ssl-server ssl-server.o ssl-client ssl-client.o
