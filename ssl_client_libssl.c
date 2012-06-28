#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SSL_CLIENT_RSA_CERT	"ssl_client.crt"
#define SSL_CLIENT_RSA_KEY	"ssl_client.key"
#define SSL_CLIENT_RSA_CA_CERT	"ssl_client_ca.crt"
#define SSL_CLIENT_RSA_CA_PATH	""

#define SSL_SERVER_ADDR		"/home/xxxx/ssl_server"

#define OFF	0
#define ON	1

int main(void)
{
	int verify_peer = OFF;
	SSL_METHOD *client_meth;
	SSL_CTX *ssl_client_ctx;
	int clientsocketfd;
	struct sockaddr_un serveraddr;
	int handshakestatus;
	SSL *clientssl;
	char buffer[1024] = "Client Hello World";

	SSL_library_init();
	SSL_load_error_strings();
	client_meth = SSLv3_client_method();
	ssl_client_ctx = SSL_CTX_new(client_meth);
	
	if(!ssl_client_ctx)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if(verify_peer)
	{	
	
		if(SSL_CTX_use_certificate_file(ssl_client_ctx, SSL_CLIENT_RSA_CERT, SSL_FILETYPE_PEM) <= 0)	
		{
			ERR_print_errors_fp(stderr);
			return -1;		
		}

	
		if(SSL_CTX_use_PrivateKey_file(ssl_client_ctx, SSL_CLIENT_RSA_KEY, SSL_FILETYPE_PEM) <= 0)	
		{
			ERR_print_errors_fp(stderr);
			return -1;		
		}
	
		if(SSL_CTX_check_private_key(ssl_client_ctx) != 1)
		{
			printf("Private and certificate is not matching\n");
			return -1;
		}	

		//See function man pages for instructions on generating CERT files
		if(!SSL_CTX_load_verify_locations(ssl_client_ctx, SSL_CLIENT_RSA_CA_CERT, NULL))
		{
			ERR_print_errors_fp(stderr);
			return -1;		
		}
		SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_verify_depth(ssl_client_ctx, 1);
	}

	if((clientsocketfd = socket(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0)) < 0)
	{
		printf("Error on socket creation\n");
		return -1;
	}
	memset(&serveraddr, 0, sizeof(struct sockraddr_un));
	serveraddr.sun_family = AF_UNIX;
	serveraddr.sun_path[0] = 0;
	strncpy(&(serveraddr.sun_path[1]), SSL_SERVER_ADDR, strlen(SSL_SERVER_ADDR) + 1);
	
	connect(clientsocketfd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_un));
		

	clientssl = SSL_new(ssl_client_ctx);
	if(!clientssl)
	{
		printf("Error SSL_new\n");
		return -1;
	}
	SSL_set_fd(clientssl, clientsocketfd);
		
	if(SSL_connect(clientssl) != 1)
	{
		printf("Handshake Error \n");
		return -1;
	}
		
	if(verify_peer)
	{
		X509 *ssl_client_cert = NULL;

		ssl_client_cert = SSL_get_peer_certificate(clientssl);
			
		if(!ssl_client_cert)
		{
			long verifyresult;

			verifyresult = SSL_get_verify_result(clientssl);
			if(verifyresult == X509_V_OK)
				printf("Certificate Verify Success\n"); 
			else
				printf("Certificate Verify Failed\n"); 
			X509_free(ssl_client_cert);				
		}
		else
			printf("There is no client certificate\n");
	}
	SSL_write(clientssl, buffer, strlen(buffer) + 1);
	SSL_read(clientssl, buffer, sizeof(buffer));
	printf("SSL server send %s\n", buffer);
	SSL_shutdown(clientssl);
	close(clientsocketfd);
	SSL_free(clientssl);
	SSL_CTX_free(ssl_client_ctx);
	return 0;	
}
