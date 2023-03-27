all: server
server: server.c
	gcc -o server server.c -lcrypto -lssl -lpthread
clean:
	rm -f server