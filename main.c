/******************************************************************************
 * Filename: main.c
 * Description:
 *
 * Version: 1.0
 * Created: Oct 09 2010 19:14:12
 * Last modified: Oct 09 2010 19:14:12
 *
 * Author: Ladislav Láska
 * e-mail: ladislav.laska@gmail.com
 *
 ******************************************************************************/

#define _XOPEN_SOURCE 500

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#define S_UNREACHABLE -1
#define S_NO_X509 -2
#define S_OK 0
#define S_WARNING 1
#define S_ERROR 2
#define S_UNKNOWN 3

int warning_after = 30;
int error_after = 7;

#define LOG_LEVEL 0

#define die(msg) { fprintf(stderr, "Error: " msg "\n" ); exit(3); }
#define gnutls_die(code) { gnutls_perror(code); exit(3); }

char errmsg[256];

void print_help();

int tcp_open( char *hostname, char *service ) {
	struct addrinfo hints;
	struct addrinfo *result, *result_ptr;
	int err, sfd;

	/* Set hints */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(hostname, service, &hints, &result);
	if (err) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
		exit(3);
	}

	for (result_ptr = result; result_ptr != NULL; result_ptr = result_ptr->ai_next) {
		sfd = socket(result_ptr->ai_family, result_ptr->ai_socktype,
						result_ptr->ai_protocol);
		if (sfd == -1) continue; 

		if (connect(sfd, result_ptr->ai_addr, result_ptr->ai_addrlen) != -1)
			break; /* Success */
		
		close(sfd);	/* connect(2) failed. */
	}

	if (result_ptr == NULL) {
		/* No address succeeded */
		return -1;
	}

	freeaddrinfo(result);

	return sfd;
}

int check( char * hostname, char *service ) {
	int state = S_OK;
	int err;

	gnutls_session_t session;
	gnutls_certificate_credentials_t xcred;

	/* x509 stuff */
	
	err = gnutls_certificate_allocate_credentials( &xcred );
	if (err < 0) gnutls_die(err);

	err = gnutls_init( &session, GNUTLS_CLIENT );
	if (err < 0) gnutls_die(err);

	/* priority init? */
	err = gnutls_priority_set_direct(session, "EXPORT", NULL);
	if (err < 0) gnutls_die(err);

	err = gnutls_credentials_set( session, GNUTLS_CRD_CERTIFICATE, xcred );
	if (err < 0) gnutls_die(err);

	/* Connect to server */

	int fd = tcp_open( hostname, service );
	
	if (fd == -1) {
		state= S_UNREACHABLE;
		goto cleanup;
	}

	/* Socket opened, establish tls connection */

	/* Associate socket with session */
	gnutls_transport_set_ptr( session, (gnutls_transport_ptr_t) fd );
	
	/* Do handshake */
	err = gnutls_handshake( session );
	if (err < 0) gnutls_die(err);
	
	/* Get server certificate. */
	const gnutls_datum_t *cert_list;
	unsigned int cert_list_size = 0;
	time_t expiration_time, today;
	gnutls_x509_crt_t cert;

	if ( gnutls_certificate_type_get( session ) != GNUTLS_CRT_X509 ) {
		state = S_NO_X509;
		goto cleanup;
	}

	cert_list = gnutls_certificate_get_peers( session, &cert_list_size );

	today = time(NULL);

	for (int i = 0; i < cert_list_size; i++) {
		gnutls_x509_crt_init( &cert );
		gnutls_x509_crt_import( cert, &cert_list[0], GNUTLS_X509_FMT_DER );
		expiration_time = gnutls_x509_crt_get_expiration_time( cert );
		int expires_in = (expiration_time - today) / 86400;
		if ((state == S_OK) && (expires_in <= warning_after)) {
			state = S_WARNING;
			sprintf(errmsg, "Certificate will expire in %i days.", expires_in);
		}
		if ((state <= S_WARNING) && (expires_in <= error_after)) {
			state = S_ERROR;
			sprintf(errmsg, "Certificate will expire in %i days.", expires_in);
		}
	}

	printf("Got %i certs.", cert_list_size);

	/* Clean up */
	err = gnutls_bye( session, GNUTLS_SHUT_WR );
	if (err < 0) gnutls_die(err);
	close( fd );
	cleanup:
	gnutls_deinit( session );
	gnutls_certificate_free_credentials( xcred );

	return state;
}

void log_func( int level, char *msg ) {
	fprintf(stderr, "[%2i] %s", level, msg);
}

/* 
 * This signal handler is wrong, but it's just a failsafe. 
 */
void sig_handler(int k) {
	fputs("Timeout.", stderr);	
	exit(S_UNKNOWN);
}

int main(int argc, char **argv) {
	char *hostname;
	char *service = NULL;

	int opt;

	while ((opt = getopt(argc, argv, "hvw:c:H:p:s:")) != -1) {
		switch (opt) {
			case 'w':
				warning_after = atoi(optarg);
				break;
			case 'c':
				error_after = atoi(optarg);
				break;
			case 'H':
				hostname = strdup(optarg);
				break;
			case 'p':			
			case 's':
				if (service != NULL) die("Only one service can be specified.");
				service = strdup(optarg);
				break;
			case 'h':
				print_help();
				exit(0);
			default: break;
		}
	}

	if (argc <= 1) die("No address to try.");

	gnutls_global_set_log_function((gnutls_log_func) log_func);
	gnutls_global_set_log_level(LOG_LEVEL);


	/* Initialize gnutls */
	int err;
	if ((err = gnutls_global_init())) {
		gnutls_perror(err);
		exit(3);
	};

	sprintf(errmsg, "OK");
	int state = 0;

	fflush(stdout);

	/* Setup alarm */
	/* TODO: doesn't work. */
	signal(SIGALRM, sig_handler);
	alarm(9*60);

	/* Do checking */
	state = check(hostname, service);
	if (state < 0)
		printf("Internal error.");
	
	gnutls_global_deinit();

	free(hostname);
	free(service);

	printf("%s\n", errmsg);
	return (state < 0) ? 127 : state;
}

void print_help() {
	printf("Help yourself.");
}
