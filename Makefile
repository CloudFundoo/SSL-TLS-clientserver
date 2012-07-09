libssl:
	gcc -o server ssl_server_libssl.c -lssl
	gcc -o client ssl_client_libssl.c -lssl
polarssl:
	gcc -o server ssl_server_polarssl.c -lpolarssl -L../lib -I../include
	gcc -o client ssl_client_polarssl.c -lpolarssl -L../lib -I../include

clean:
	rm -rf server client
	

