#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/pem.h"

#define SSL_CLIENT_RSA_CERT		"/home/nmathew/cacert/ssl_client.crt"
#define SSL_CLIENT_RSA_KEY		"/home/nmathew/cacert/ssl_client.key"
#define SSL_CLIENT_RSA_CA_CERT	"/home/nmathew/cacert/ca.crt"
#define SSL_CLIENT_RSA_CA_PATH	"/home/nmathew/cacert/"

#define SSL_SERVER_ADDR			"/home/nmathew/ssl_server"

#define CURRENT_SSL_CLIENT_DEBUG_LEVEL	0

void polarssl_pem_password_callback(char *buffer, int *size)
{
	*size = scanf("%s", buffer);
}

void ssl_client_debug(void *ssl_client_ctx, int level, const char* str)
{
	if(level < CURRENT_SSL_CLIENT_DEBUG_LEVEL)
	{
		fprintf((FILE *)ssl_client_ctx, "%s", str);
		fflush((FILE *)ssl_client_ctx);
	}
}


int main(void)
{
	int ret;
	int verify_peer = 0;
	entropy_context ssl_client_entropy;
	ctr_drbg_context ssl_client_ctr_drbg;
	ssl_context clientssl;
	ssl_session sslclientsession;
	x509_cert ssl_client_cert;
	rsa_context ssl_client_rsa;
	struct sockaddr_un serveraddr;
	char *owner = "ssl_client";
	int clientsocketfd;
	char buffer[1024] = "Client Hello World";

	memset(&clientssl, 0, sizeof(ssl_context));
	memset(&sslclientsession, 0, sizeof(ssl_session));
	memset(&ssl_client_cert, 0, sizeof(x509_cert));
	memset(&ssl_client_rsa, 0, sizeof(rsa_context));

	entropy_init(&ssl_client_entropy);
	if((ret = ctr_drbg_init(&ssl_client_ctr_drbg, entropy_func, &ssl_client_entropy, (unsigned char *)owner, strlen(owner))) != 0)
	{
		printf("ctr_drbg_init failed returned %d\n", ret);
		return -1;
	}
	
	if((ret = x509parse_crtfile(&ssl_client_cert, SSL_CLIENT_RSA_CERT)) != 0)
	{
		printf("x509parse_crtfile CLIENT CERT returned %d\n", ret);
		return -1;
	}

	if((ret = x509parse_keyfile(&ssl_client_rsa, SSL_CLIENT_RSA_KEY, NULL)) != 0)
	{
		if(ret == POLARSSL_ERR_PEM_PASSWORD_REQUIRED)
		{	
			char buffer[100];
			int size;

			polarssl_pem_password_callback(buffer, &size);
			if((ret = x509parse_keyfile(&ssl_client_rsa, SSL_CLIENT_RSA_KEY, buffer)) != 0)
			{
				printf("x509parse_keyfile CLIENT KEY returned %d\n", ret);
				return -1;
			}
		}
	}
	
	if((clientsocketfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		printf("Error in socket creation%d\n", clientsocketfd);
		return -1;
	}
	memset(&serveraddr, 0, sizeof(struct sockaddr_un));
	serveraddr.sun_family = AF_UNIX;
	serveraddr.sun_path[0] = 0;
	strncpy(&(serveraddr.sun_path[1]), SSL_SERVER_ADDR, strlen(SSL_SERVER_ADDR) + 1);
	if(ret = connect(clientsocketfd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_un)))
	{
		printf("connect returned error %d\n", ret);
		return -1;
	}	
	if(ret = ssl_init(&clientssl))
	{
		printf("ssl_init failed returned %d\n", ret);
		return -1;
	}
	ssl_set_endpoint(&clientssl, SSL_IS_CLIENT);
	ssl_set_authmode(&clientssl, SSL_VERIFY_NONE);
	
	if(verify_peer)
		ssl_set_authmode(&clientssl, SSL_VERIFY_REQUIRED);
	ssl_set_rng(&clientssl, ctr_drbg_random, &ssl_client_ctr_drbg);
	ssl_set_dbg(&clientssl, ssl_client_debug, stdout);
	ssl_set_bio(&clientssl, net_recv, &clientsocketfd, net_send, &clientsocketfd);
	ssl_set_ciphersuites(&clientssl, ssl_default_ciphersuites);	
	ssl_set_session(&clientssl, 1, 600, &sslclientsession);
	ssl_set_own_cert(&clientssl, &ssl_client_cert, &ssl_client_rsa);
	
	if(ret = ssl_handshake(&clientssl))
	{
		printf("handshake failed returned %d\n", ret);
		return -1;
	}
	if((ret = ssl_write(&clientssl, buffer, strlen(buffer) + 1)) <= 0)
	{
		printf("ssl_write failed returned %d\n", ret);
		return -1;
	}
	if((ret = ssl_read(&clientssl, buffer, sizeof(buffer))) <= 0)
	{
		printf("ssl_read failed returned %d\n", ret);
		return -1;
	}
	printf("SSL server send %s\n", buffer);
	ssl_close_notify(&clientssl);
	net_close(clientsocketfd);
	x509_free(&ssl_client_cert);
	rsa_free(&ssl_client_rsa);
	ssl_free(&clientssl);
	
	return 0;
}
