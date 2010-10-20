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
