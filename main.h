/******************************************************************************
 * Filename: main.h
 * Description:
 *
 * Version: 1.0
 * Created: Oct 20 2010 17:38:43
 * Last modified: Oct 20 2010 17:38:43
 *
 * Author: Ladislav Láska
 * e-mail: ladislav.laska@gmail.com
 *
 ******************************************************************************/
#ifndef _MAIN_H_
#define _MAIN_H_

#include <stdio.h>
#include <stdlib.h>
#include <gnutls/gnutls.h>

enum {
	S_UNREACHABLE = -1,
	S_NO_X509 = -2,
	S_OK = 0,
	S_WARNING = 1,
	S_ERROR = 2,
	S_UNKNOWN = 3,
};

#define BUFFER_SIZE 1024


#define die(msg) { fprintf(stderr, "Error: " msg "\n" ); exit(S_ERROR); }
#define dief(msg, ...) { fprintf(stderr, "Error: " msg "\n", __VA_ARGS__ ); exit(S_ERROR); }
#define gnutls_die(code) { gnutls_perror(code); exit(S_ERROR); }

#endif
