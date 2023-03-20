all: server client
server: server.c
	gcc -o server server.c -lssl -lcrypto -lpthread
client: client.c
	gcc -o client client.c -lssl -lcrypto -lpthread
clean:
	rm -f server client