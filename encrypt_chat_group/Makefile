all: server client
server: server.c
	gcc -o server server.c -lssl -lpthread -lcrypto
client: client.c
	gcc -o client client.c -lpthread -lssl -lcrypto
clean:
	rm -f server client