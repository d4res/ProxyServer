target: client server

server: server.c
	gcc -o $@ $^ -pthread

server_uctl: server.c
	gcc -o $@ $^ -pthread -D USERCTL

server_phish: server.c
	gcc -o $@ $^ -pthread -D PHISH

server_filter: server.c
	gcc -o $@ $^ -pthread -D FILTER

clean:
	rm server