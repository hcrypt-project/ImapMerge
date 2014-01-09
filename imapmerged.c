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
#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

int checkMulti(char *s);
int readLine(int sockfd,SSL *ssl,char *buf,int size);
char *stripCrlf(char *s);
SSL_CTX* InitServerCTX(void);
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
void ShowCerts(SSL* ssl);
char *strstr_nocase(char *haystack, char *needle);

int tlsmode=0;
char myhaystack[4096],myneedle[4096];

int main(int argc, char *argv[])
{
    int listenfd = 0, clientfd = 0;
    int logout=0,multi=0,starttls=0,fetch=0;
	int serverfd = 0, n = 0;

	struct sockaddr_in serv_addr;
	struct sockaddr_in imap_addr;

	char clBuff[1025];
    char svBuff[1025];

    //const SSL_METHOD *method,*cl_method;
    SSL_CTX *ctx,*cl_ctx;
    SSL *ssl,*cl_ssl;

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
    //method = SSLv23_client_method();

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));


    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(1143);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    listen(listenfd, 10);



    while(1)
    {
    	puts("imapmerged: proxy ready.");
        clientfd = accept(listenfd, (struct sockaddr*)NULL, NULL);

        puts("imapmerged: client connected.");
        ////
        memset(svBuff, '0',sizeof(svBuff));
		memset(clBuff, '0',sizeof(clBuff));
		if((serverfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			printf("imapmerged: could not create socket.\n");
			return 1;
		}

		memset(&imap_addr, '0', sizeof(imap_addr));

		imap_addr.sin_family = AF_INET;
		imap_addr.sin_port = htons(143);

		// rrzn "130.75.6.238"
		// schlund "212.227.15.188"
		//o2online "91.136.8.190"
		if(inet_pton(AF_INET, "212.227.15.188", &imap_addr.sin_addr)<=0)
		{
			printf("imapmerged: inet_pton error occured.\n");
			return 1;
		}

		if( connect(serverfd, (struct sockaddr *)&imap_addr, sizeof(imap_addr)) < 0)
		{
		   printf("imapmerged: server connect failed.\n");
		   return 1;
		}

		puts("imapmerged: connected to remote IMAP server.");

		// read server info message
		if( (n = readLine(serverfd, NULL, svBuff, sizeof(svBuff)-1)) > 0)
		{
			//recvBuff[n] = 0;
			printf("imapmerged: server string(%d)=%s.\n",n,stripCrlf(svBuff));

		}
		else if(n<0)
		{
			printf("imapmerged: server string read error.\n");
			return -1;
		}

		// forward server info message
		write(clientfd, svBuff, n);
		puts("imapmerged: server string delivered.");fflush(stdout);

		logout=0;
		starttls=0;
		tlsmode=0;
		ssl=NULL;
		fetch=0;

		while(!logout)
		{


			printf("imapmerged: waiting for client command (%s).\n",tlsmode?"TLS":"PLAIN");

//			if(tlsmode)
//			{
//				res=SSL_peek(ssl,peek,100);
//				peek[res]=0;
//				printf("imapmerged: peek server socket=(%d)'%s'\n",res,peek);
//			}
			// read client command
			if ( (n = readLine(clientfd, tlsmode?cl_ssl:NULL, clBuff, sizeof(clBuff)-1)) > 0)
			{
				//recvBuff[n] = 0;
				printf("imapmerged: client=(%d)'%s'.\n",n,stripCrlf(clBuff));
			}
			else if(n<0)
			{
				printf("imapmerged: read error.\n");
				return -1;
			}

			if(strstr_nocase(clBuff," LOGOUT"))
			{
				logout=1;
				puts("imapmerged: LOGOUT requested.");
			}

			if(strstr_nocase(clBuff," STARTTLS"))
			{
				starttls=1;
				//logout=1;
				puts("imapmerged: STARTTLS requested.");
			}
			/////
			if(strstr_nocase(clBuff," UID FETCH "))
			{
				puts("imapmerged: uid fetch started");
				fetch=1;
			}

			if(!tlsmode||ssl==NULL)
				write(serverfd, clBuff, n);
			else //if(tlsmode)
			{
				SSL_write(ssl, clBuff, n);
			}

			puts("imapmerged: start multiline processing.");
			multi=1;
			while(multi)
			{
				if ( (n = readLine(serverfd, ssl, svBuff, sizeof(svBuff)-1)) > 0)
				{
					//recvBuff[n] = 0;
					printf("imapmerged: server='%s'.\n",stripCrlf(svBuff));

//					if(!memcmp(svBuff,"2 OK Completed",14))
//					{
//						puts("imapmerged: try proxy login");
//						SSL_write(ssl,"3 LOGIN brenner@rrzn.uni-hannover.de iQM796T4\r\n",49);
//						n = readLine(serverfd, ssl, svBuff, sizeof(svBuff)-1);
//					}

					if(!starttls&&!tlsmode)
					{
						write(clientfd, svBuff, n);
						//puts("imapmerged: server message delivered (plain).");
					}

					if(tlsmode)
					{
						SSL_write(cl_ssl, svBuff, n);
						//printf("imapmerged: server message delivered (TLS,res=%d).\n",res);
					}

					if(fetch)
					{
						if(strstr_nocase(svBuff," OK UID FETCH COMPLETED")) //NO BAD
						{
							fetch=0;
							puts("imapmerged: uid fetch completed");
							multi=0;
						}
					}
					else if(*svBuff!='*')
					{
						if(strstr(svBuff," OK ")) // NO BAD
							multi=0;

						if(!memcmp(svBuff,"+ \r\n",4))
							multi=0;
					}
				}
				else
				{
					printf("imapmerged: read error 2.\n");
					//return -1;
				}
				/////

			}
			puts("imapmerged: server message processed.");fflush(stdout);

			if(starttls)
			{
				printf("imapmerged: starting TLS to IMAP server.\n");

				if ( (ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
				{
					puts("imapmerged: ssl context failed.");
					return -1;
				}
				//SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

				ssl = SSL_new(ctx);
				SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

				SSL_set_fd(ssl, serverfd);

				if ( SSL_connect(ssl) != 1 )
					puts("imapmerged: TLS server negotiation failed.");
				else
					puts("imapmerged: TLS server negotiation successful.");

				puts("imapmerged: starting TLS to client.");
/*
			    cl_ctx = SSL_CTX_new(SSLv23_server_method());
			    if ( cl_ctx == NULL )
			    {
			    	puts("imapmerged: ssl context failed.");
			    	return -1;
			    }
			    SSL_CTX_set_options(cl_ctx, SSL_OP_ALL);

				cl_ssl = SSL_new(cl_ctx);
				if(cl_ssl==NULL)
				{
					puts("imapmerged: TLS server socket failed.");
					return -1;
				}
				SSL_clear(cl_ssl);

				SSL_set_fd(cl_ssl, clientfd);
				SSL_set_accept_state(cl_ssl);

*/

				cl_ctx = InitServerCTX();        /* initialize SSL */
			    LoadCertificates(cl_ctx, "/usr/share/doc/libssl-doc/demos/sign/cert.pem", "/usr/share/doc/libssl-doc/demos/sign/key.pem"); /* load certs */
			    cl_ssl = SSL_new(cl_ctx);              /* get new SSL state with context */
			    SSL_set_mode(cl_ssl, SSL_MODE_AUTO_RETRY);
			    SSL_set_fd(cl_ssl, clientfd);      /* set connection socket to SSL state */
				printf("imapmerged: deliver TLS starter '%s'.\n",stripCrlf(svBuff));
				write(clientfd, svBuff, n); //'OK begin negotiation' ausliefern

				if ( SSL_accept(cl_ssl) == -1 )     /* do SSL-protocol accept */
				{
					ERR_print_errors_fp(stderr);
					printf("imapmerged: TLS client negotiation failed (%d).\n",SSL_get_error(cl_ssl,-1));
				}
				else
				{
					puts("imapmerged: TLS client negotiation successful.");
					//logout=1;
				}
				//SSL_clear(cl_ssl);
/*
				if ( SSL_accept(cl_ssl) == -1 )
				{
					printf("imapmerged: TLS client negotiation failed (%d)\n",SSL_get_error(cl_ssl,-1));
				}
				else
					puts("imapmerged: TLS client negotiation successful");
*/

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

			printf("imapmerged: TLS shutdown state=%d (%s).\n",n,n==1?"fine":"error");
			if(n!=1)
				printf("imapmerged: TLS shutdown error=%d.\n",SSL_get_error(ssl,n));

		}
		close(clientfd);
		puts("imapmerged: client connection closed.");
		close(serverfd);
		puts("imapmerged: remote IMAP connection closed.");

		if(tlsmode)
		{
			SSL_free(ssl);
			SSL_free(cl_ssl);
			SSL_CTX_free(ctx);
			SSL_CTX_free(cl_ctx);
		}
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
	int loop=0;

	while(r<size)
	{
		if(!tlsmode||(ssl==NULL))
		{
			if ( (n = read(sockfd, buf+r, 1)) > 0)
			{
				//printf("+");
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
			else
			{
				if(!loop)
				{
					puts("imapmerged: plain readLine loops");
					loop=1;
				}
			}
		}
		else
		{
//			if(loop)
//			{
//				int res;
//				char peek[100];
//				puts("imapmerged: sleep.\n");
//				res=SSL_peek(ssl,peek,100);
//				peek[res]=0;
//				printf("imapmerged: peek server socket=(%d)'%s'\n",res,peek);
//				sleep(1);
//			}
			if ( (n = SSL_read(ssl, buf+r, 1)) > 0)
			{
				//printf("#");
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
			else
			{
				//ERR_print_errors_fp(stderr);
				if(!loop)
				{
					puts("imapmerged: tls readLine loops");
					loop=1;
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
		if((c=(char*)strstr(stripBuf,"\r\n")))
			*c=0;
	}
	return stripBuf;
}

SSL_CTX* InitServerCTX(void)
{   //SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    //method = SSLv3_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(SSLv3_server_method());   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    //New lines
    if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
        ERR_print_errors_fp(stderr);

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);
    //End new lines

    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }

    //New lines - Force the client-side have a certificate
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    //End new lines
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

char *strstr_nocase(char *haystack, char *needle)
{
	char *result;
	int i,a,b;

	a=strlen(haystack);
	b=strlen(needle);

	for(i=0;i<a&&i<4096;i++)
		myhaystack[i]=toupper(haystack[i]);

	myhaystack[a]=0;

	for(i=0;i<b&&i<4096;i++)
		myneedle[i]=toupper(needle[i]);

	myneedle[b]=0;

	result=strstr(myhaystack,myneedle);

	//printf("strstr_nocase: '%s' '%s' = %d\n",myneedle,myhaystack,result);

	return result;
}
