#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/pem.h"

#define SSL_SERVER_RSA_CERT	"/home/nmathew/cacert/ssl_server.crt"
#define SSL_SERVER_RSA_KEY	"/home/nmathew/cacert/ssl_server.key"
#define SSL_SERVER_RSA_CA_CERT	"/home/nmathew/cacert/ca.crt"
#define SSL_SERVER_RSA_CA_PATH	"/home/nmathew/cacert/"

#define SSL_SERVER_ADDR		"/home/nmathew/ssl_server"

#define CURRENT_SSL_SERVER_DEBUG_LEVEL	0


char *ssl_server_dh_P = 
	"D49E7B8E0D64CBA62CCC63FB4611"
	"AE52737930500E7C3B25CF6CC411"
	"48FF52A6FE9BA25D1B6E2B994654"
	"4C8688E134C111EB205F79DF6B64"
	"DB384A9474654C779072DE33625D"
	"D530FBC938AA8AFA02EEA9EC3E80"
	"57C36E259EB6F8EBDC3CA1C6E926"
	"CAD0E8CBDB2582D4B65F09AEB55C"
	"C2D3A2600D318013DEBFE491A5E4E133";
char *ssl_server_dh_G = "4";

int ssl_server_ciphersuites[]=
{
	SSL_EDH_RSA_AES_256_SHA,
	SSL_EDH_RSA_CAMELLIA_256_SHA,
	SSL_EDH_RSA_AES_128_SHA,
	SSL_EDH_RSA_CAMELLIA_128_SHA,
	SSL_EDH_RSA_DES_168_SHA,
	SSL_RSA_AES_256_SHA,
	SSL_RSA_CAMELLIA_256_SHA,
	SSL_RSA_AES_128_SHA,
	SSL_RSA_CAMELLIA_128_SHA,
	SSL_RSA_DES_168_SHA,
	SSL_RSA_RC4_128_SHA,
	SSL_RSA_RC4_128_MD5,
	0
};
	
int polarssl_pem_password_callback(char *buffer, int *size)
{	
	*size = scanf("%s", buffer);	
}

ssl_session *ssl_session_list = NULL;
ssl_session *current, *prev;

void free_session_list(void)
{
	current = ssl_session_list;
	
	while(!current)
	{
		prev = current;
		current = current->next;
		memset(prev, 0, sizeof(ssl_session));
		free(prev);
	}
	return;
}

static int ssl_server_get_session(ssl_context *session)
{
	time_t t = time(NULL);
	
	if(session->resume == 0)
		return 1;

	current = ssl_session_list;
	prev = NULL;

	while(current != NULL)
	{
		prev = current;
		current = current->next;

		if(session->timeout != 0 && (int) (t - prev->start) > session->timeout)
			continue;
		if(session->session->ciphersuite != prev->ciphersuite || 
			session->session->length != prev->length)
			continue;
		if(memcmp(session->session->id, prev->id, prev->length) != 0)
			continue;
		memcpy(session->session->master, prev->master, 48);
		return 0;
	}
	return 1;
}
static int ssl_server_set_session(ssl_context *session)
{
	time_t t = time(NULL);
	
	current = ssl_session_list;
	prev = NULL;

	while(current)
	{
		if(session->timeout != 0 && (int)(t - current->start) > session->timeout)
			break;
		if(memcmp(session->session->id, current->id, current->length) == 0)
			break;
		prev = current;
		current = current->next;
	}
	
	if(!current)
	{
		current = (ssl_session *)malloc(sizeof(ssl_session));
		if(!current)
			return 1;
		if(!prev)
			ssl_session_list;
		else
			prev->next = current;
	}
	memcpy(current, session->session, sizeof(ssl_session));
	return 0;
}

void ssl_server_debug(void *ssl_server_ctx, int level, const char *str)
{
	if(level < CURRENT_SSL_SERVER_DEBUG_LEVEL)
	{
		fprintf((FILE *)ssl_server_ctx, "%s", str);
		fflush((FILE *)ssl_server_ctx);
	}		
}

int main(void)
{
	int ret;
	int verify_peer = 0;
	x509_cert ssl_server_crt;
	rsa_context ssl_server_rsa;
	struct sockaddr_un serveraddr;
	ctr_drbg_context ssl_server_ctr_drbg;
	entropy_context ssl_server_entropy;
	ssl_context serverssl;
	ssl_session sslserversession;
	int serversocketfd;
	char *owner = "ssl_server";

	memset(&ssl_server_crt, 0, sizeof(x509_cert));
	if((ret = x509parse_crtfile(&ssl_server_crt, SSL_SERVER_RSA_CERT)) !=0 )
	{
		printf("x509parse_crtfile SERVER CERT returned %d\n", ret);
		return -1;
	}

	rsa_init(&ssl_server_rsa, RSA_PKCS_V15, 0);

	if((ret = x509parse_keyfile(&ssl_server_rsa, SSL_SERVER_RSA_KEY, NULL)) !=0 )
	{
		if(ret == POLARSSL_ERR_PEM_PASSWORD_REQUIRED)
		{
			char buffer[100];
			int size;
           
			polarssl_pem_password_callback(buffer, &size);
			
			if((ret = x509parse_keyfile(&ssl_server_rsa, SSL_SERVER_RSA_KEY, buffer)) !=0 )
			{
				printf("x509parse_keyfile SERVER KEY returned %d\n", ret);
				return -1;
			}
		}
	}
	if((serversocketfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{	
		printf("Error in socket creation %d\n", serversocketfd);
		return -1;
	}
	
	memset(&serveraddr, 0 , sizeof(struct sockaddr_un));
	serveraddr.sun_family = AF_UNIX;
	serveraddr.sun_path[0] = 0;
	strncpy(&(serveraddr.sun_path[1]), SSL_SERVER_ADDR, strlen(SSL_SERVER_ADDR) + 1);
	if(bind(serversocketfd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_un)))
	{
		printf("server bind error\n");
		return -1;
	}
	
	if(listen(serversocketfd, SOMAXCONN))
	{
		printf("Error on listen\n");
		return -1;
	}
	
	entropy_init(&ssl_server_entropy);
	if( (ret = ctr_drbg_init(&ssl_server_ctr_drbg, entropy_func, &ssl_server_entropy, owner, strlen(owner))) != 0)
	{
		printf("ctr_drbg_init failed & returned %d\n", ret);
		return -1;
	}
	if( (ret = ssl_init(&serverssl)) != 0)
	{
		printf("ssl_init failed & returned %d\n", ret);
		return -1;
	}

	ssl_set_endpoint(&serverssl, SSL_IS_SERVER);
	ssl_set_authmode(&serverssl, SSL_VERIFY_NONE);
	if(verify_peer)
		ssl_set_authmode(&serverssl, SSL_VERIFY_REQUIRED);
		
	ssl_set_rng(&serverssl, ctr_drbg_random, &ssl_server_ctr_drbg);
	ssl_set_dbg(&serverssl, ssl_server_debug, stdout);	
	ssl_set_scb(&serverssl, ssl_server_get_session, ssl_server_set_session);
	ssl_set_ciphersuites(&serverssl, ssl_server_ciphersuites);
	ssl_set_session(&serverssl, 1, 0, &sslserversession);
	memset(&sslserversession, 0, sizeof(ssl_session));
	//ssl_set_ca_chain(&serverssl, ssl_server_crt.next, NULL, NULL);
	ssl_set_own_cert(&serverssl, &ssl_server_crt, &ssl_server_rsa);
	ssl_set_dh_param(&serverssl, ssl_server_dh_P, ssl_server_dh_G);

	while(1)
	{
		int clientsocketfd;
		char buffer[1024];
		int bytesread;
		int addedstrlen;
		
		clientsocketfd = accept(serversocketfd, NULL, 0);
		ssl_session_reset(&serverssl);
		ssl_set_bio(&serverssl, net_recv, &clientsocketfd, net_send, &clientsocketfd);
		if((ret = ssl_handshake(&serverssl)) != 0)
		{
			printf("ssl_handshake failed %d\n", ret);
			return -1;
		}		
		bytesread = ssl_read(&serverssl, buffer, sizeof(buffer));
		addedstrlen = strlen("Appended by SSL Server");
		strncpy(&buffer[bytesread], "Appended by SSL Server", addedstrlen);
		buffer[bytesread + addedstrlen] = '\0';
		ssl_write(&serverssl, buffer, bytesread + addedstrlen + 1);
		ssl_close_notify(&serverssl);
		net_close(clientsocketfd);
	}
	x509_free(&ssl_server_crt);
	rsa_free(&ssl_server_rsa);
	ssl_free(&serverssl);
	close(serversocketfd);
	free_session_list();
	
	return 0;
}
