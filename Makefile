libssl:
	gcc -o server ssl_server_libssl.c -lssl -lcrypto
	gcc -o client ssl_client_libssl.c -lssl -lcrypto
polarssl:
	gcc -o server ssl_server_polarssl.c -lpolarssl -L../lib -I../include -lcrypto
	gcc -o client ssl_client_polarssl.c -lpolarssl -L../lib -I../include -lcrypto

clean:
	rm -rf server client
