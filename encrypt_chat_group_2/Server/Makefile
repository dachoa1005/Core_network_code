all: server
server: server.c
	gcc -o server server.c -lcrypto -lssl
clean:
	rm -f server