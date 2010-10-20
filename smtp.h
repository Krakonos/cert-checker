/******************************************************************************
 * Filename: smtp.h
 * Description:
 *
 * Version: 1.0
 * Created: Oct 20 2010 17:34:54
 * Last modified: Oct 20 2010 17:34:54
 *
 * Author: Ladislav Láska
 * e-mail: ladislav.laska@gmail.com
 *
 ******************************************************************************/
#ifndef _SMTP_H_
#define _SMTP_H_

int smtp_ehlo(int fd);
char* smtp_expect(int fd, char *str);
int smtp_starttls(int fd);

#endif
