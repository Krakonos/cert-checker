/******************************************************************************
 * Filename: smtp.c
 * Description: Simple smtp handling routines for cert-checker
 *
 * Version: 1.0
 * Created: Oct 20 2010 17:31:31
 * Last modified: Oct 20 2010 17:31:31
 *
 * Author: Ladislav Láska
 * e-mail: ladislav.laska@gmail.com
 *
 ******************************************************************************/

#define _XOPEN_SOURCE 500

#include <gnutls/gnutls.h>

#include <unistd.h>
#include <string.h>

#include "main.h"

/* Expect status code */
char* smtp_expect(int fd, char *str) {
	char buffer[BUFFER_SIZE];
	int len = strlen(str);
	int bytes = read(fd, buffer, BUFFER_SIZE);
	if (bytes < len) goto fail;
	if (!strncmp(buffer,str,len)) {
		while (bytes == BUFFER_SIZE)
			bytes = read(fd, buffer, BUFFER_SIZE) > 0;
		return NULL;
	}

	fail:;
	char *ptr = strdup(buffer);
	while (bytes == BUFFER_SIZE)
		bytes = read(fd, buffer, BUFFER_SIZE) > 0;
	return ptr;
}

/* Expect status code. This can be done better. */
char* ssl_smtp_expect(gnutls_session_t session, char *str) {
	char buffer[BUFFER_SIZE];
	int len = strlen(str);
	int bytes = gnutls_record_recv(session, buffer, BUFFER_SIZE);
	if (bytes < len) goto fail;
	if (!strncmp(buffer,str,len)) {
		return NULL;
	}

	fail:;
	return strdup(buffer);
}

/* Send EHLO and check for STARTTLS extension. */
int smtp_ehlo(int fd) {
	return 0;
}

int smtp_starttls(int fd) {
	smtp_expect(fd, "220"); /* Read everything in buffer */
	char buffer[] = "STARTTLS\n";
	write(fd, buffer, sizeof(buffer));
	char *b;
	if ((b = smtp_expect(fd, "220 "))) {
		dief("STARTTLS declined: %s.", b);
	}
	return 0;
}

/* Ugly, sending could fail and  other horrible things may happen. */
int smtp_quit(gnutls_session_t session) {
	char buffer[] = "QUIT\n";
	int sent = GNUTLS_E_AGAIN;
	sent = gnutls_record_send(session, buffer, sizeof(buffer));
	
	ssl_smtp_expect(session, "221 ");

	/* TODO: Better (read: some) error handling. */
	return 0;
}
