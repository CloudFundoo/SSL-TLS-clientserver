libssl:
	gcc -o server ssl_server_libssl.c -lssl
	gcc -o client ssl_client_libssl.c -lssl
polarssl:

clean:
	rm -rf server client
	

