/*
 * imapmerged.c
 *
 *  Created on: 03.01.2014
 *      Author: micha
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

int checkMulti(char *s);
int readLine(int sockfd,SSL *ssl,char *buf,int size);
char *stripCrlf(char *s);

int tlsmode=0;

int main(int argc, char *argv[])
{
    int listenfd = 0, clientfd = 0;
    int logout=0,multi=0,starttls=0;
	int serverfd = 0, n = 0;

	struct sockaddr_in serv_addr;
	struct sockaddr_in imap_addr;

	char clBuff[1025];
    char svBuff[1025];

    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;

    puts("imapmerged: starting.");

    puts("imapmerged: setting up openssl.");
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    if(SSL_library_init() < 0)
    {
    	puts("imapmerged: openssl init failed.");
    	return -1;
    }
    method = SSLv23_client_method();

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));


    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(1143);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    listen(listenfd, 10);

    puts("imapmerged: proxy ready.");

    while(1)
    {
        clientfd = accept(listenfd, (struct sockaddr*)NULL, NULL);

        puts("imapmerged: client connected.");
        ////
        memset(svBuff, '0',sizeof(svBuff));
		memset(clBuff, '0',sizeof(clBuff));
		if((serverfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			printf("imapmerged: could not create socket \n");
			return 1;
		}

		memset(&imap_addr, '0', sizeof(imap_addr));

		imap_addr.sin_family = AF_INET;
		imap_addr.sin_port = htons(143);

		// rrzn "130.75.6.238"
		// schlund "212.227.15.188"
		//o2online "91.136.8.190"
		if(inet_pton(AF_INET, "91.136.8.190", &imap_addr.sin_addr)<=0)
		{
			printf("imapmerged: inet_pton error occured\n");
			return 1;
		}

		if( connect(serverfd, (struct sockaddr *)&imap_addr, sizeof(imap_addr)) < 0)
		{
		   printf("imapmerged: connect failed \n");
		   return 1;
		}

		puts("imapmerged: connected to remote IMAP server.");

		// read server info message
		if( (n = readLine(serverfd, NULL, svBuff, sizeof(svBuff)-1)) > 0)
		{
			//recvBuff[n] = 0;
			printf("imapmerged: server string(%d)=%s\n",n,stripCrlf(svBuff));

		}
		else if(n<0)
		{
			printf("imapmerged: server string read error \n");
			return -1;
		}

		// forward server info message
		write(clientfd, svBuff, n);
		puts("imapmerged: server string delivered.");fflush(stdout);

		logout=0;
		starttls=0;
		tlsmode=0;
		ssl=NULL;

		while(!logout)
		{
			// read client command
			if ( (n = readLine(clientfd, NULL, clBuff, sizeof(clBuff)-1)) > 0)
			{
				//recvBuff[n] = 0;
				printf("imapmerged: client='%s'\n",stripCrlf(clBuff));
			}
			else if(n<0)
			{
				printf("imapmerged: read error \n");
				return -1;
			}

			if(strstr(clBuff," LOGOUT"))
			{
				logout=1;
				puts("imapmerged: LOGOUT requested.");
			}

			if(strstr(clBuff," STARTTLS"))
			{
				starttls=1;
				//logout=1;
				puts("imapmerged: STARTTLS requested.");
			}
			/////
			if(!tlsmode||ssl==NULL)
				write(serverfd, clBuff, n);
			else
				SSL_write(ssl, clBuff, n);

			puts("imapmerged: start multiline processing.");
			multi=1;
			while(multi)
			{
				if ( (n = readLine(serverfd, ssl, svBuff, sizeof(svBuff)-1)) > 0)
				{
					//recvBuff[n] = 0;
					printf("imapmerged: server='%s'\n",stripCrlf(svBuff));
					write(clientfd, svBuff, n);
					if(*svBuff!='*')
						multi=0;
				}
				else
				{
					printf("imapmerged: read error \n");
					return -1;
				}
				/////

			}
			puts("imapmerged: server message processed.");fflush(stdout);

			if(starttls)
			{
				printf("imapmerged: starting TLS\n");

				if ( (ctx = SSL_CTX_new(method)) == NULL)
				{
					puts("imapmerged: ssl context failed.");
					return -1;
				}
				//SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

				ssl = SSL_new(ctx);

				SSL_set_fd(ssl, serverfd);

				if ( SSL_connect(ssl) != 1 )
					puts("imapmerged: TLS negotiation failed.");
				else
					puts("imapmerged: TLS negotiation successful.");

				tlsmode=1;
				starttls=0;
			}

		}

		if(tlsmode)
		{
			puts("imapmerged: shutting down TLS session.");
			if( SSL_ST_OK == SSL_state( ssl ) )
			{
				n = SSL_shutdown( ssl );
				if( n == 0 )
				{
				  n = SSL_shutdown( ssl );
				}
			}

			printf("imapmerged: TLS shutdown state=%d (%s)\n",n,n==1?"fine":"error");
		}
		close(clientfd);
		puts("imapmerged: client connection closed.");
		close(serverfd);
		puts("imapmerged: remote IMAP connection closed.");
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		fflush(stdout);
     }
}

int checkMulti(char *s)
{
	int i,c;

	i=strlen(s)-1;
	c=2;
	while(i>=0&&c>0)
	{
		if(s[i]=='\n')
			c--;
		i--;
	}
	printf("check: %02x\n",s[i+1]);
	return s[i+1]=='*';

}

int readLine(int sockfd,SSL *ssl,char *buf,int size)
{
	int r=0,n=0;

	while(r<size)
	{
		if(!tlsmode||(ssl==NULL))
		{
			if ( (n = read(sockfd, buf+r, 1)) > 0)
			{
				r++;
				if(r>1)
				{
					if(!memcmp(buf+r-2,"\r\n",2))
					{
						buf[r]=0;
						return r;
					}
				}
			}
		}
		else
		{
			if ( (n = SSL_read(ssl, buf+r, 1)) > 0)
			{
				r++;
				if(r>1)
				{
					if(!memcmp(buf+r-2,"\r\n",2))
					{
						buf[r]=0;
						return r;
					}
				}
			}
		}
	}
	return -1;
}

char *stripCrlf(char *s)
{
	static char stripBuf[4096];
	char *c;

	if(strlen(s)>sizeof(stripBuf))
		strcpy(stripBuf,"(null)");
	else
	{
		strcpy(stripBuf,s);
		if(c=(char*)strstr(stripBuf,"\r\n"))
			*c=0;
	}
	return stripBuf;
}
