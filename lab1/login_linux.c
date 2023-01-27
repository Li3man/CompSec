/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

void sighandler() {
	/* add signalhandling routines here */
	/* see 'man 2 signal' */
    signal(SIGINT, SIG_IGN); /* ignore Ctrl-C */
    signal(SIGTSTP, SIG_IGN); /* ignore Ctrl-Z */
    signal(SIGABRT, SIG_IGN); /* ignore Ctrl-\ */
}

int main(int argc, char *argv[]) {
    mypwent *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */
	char important1[LENGTH] = "**IMPORTANT 1**";
	char user[LENGTH];
	char important2[LENGTH] = "**IMPORTANT 2**";
	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;
    FILE *fp;
    char str[150];

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

        char res;
        res = fgets(user, LENGTH, stdin);
		if (res == NULL){
            exit(0); /*  overflow attacks.  */
        }else{
            user[strcspn(user, "\n")] = '\0'; /* replace \n with \0 */
        }


		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */

            /* Make sure only three attemps is allowed */
            if(passwddata->pwfailed >= 3){
                printf("Too many tries! Account is locked!");
                break;
            }

			if (!strcmp(user_pass, passwddata->passwd)) {

				printf(" You're in !\n");
                passwddata->pwfailed = 0; /* reset fail counter */
                passwddata->pwage++; /* increase age counter */
                if(passwddata->pwage >= 10){
                    printf("The account password need to be changed! NOW!");
                }

                /* update file content */
                fp = fopen(MYPWENT_FILENAME,"r+");
                if(fp != NULL){
                    sprintf(str, "%s:%d:%s:%s:%d:%d", passwddata->pwname, passwddata->uid, passwddata->passwd, passwddata->passwd_salt,
                            passwddata->pwfailed, passwddata->pwage);
                    fputs(str, fp);
                    fclose(fp);
                }
				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */
                setuid(passwddata->uid);
                execve("/bin/sh", NULL, NULL);

			}else{
                passwddata->pwfailed++; /* Increase fail counter */

                /* update file content */
                fp = fopen(MYPWENT_FILENAME,"r+");
                if(fp != NULL){
                    sprintf(str, "%s:%d:%s:%s:%d:%d", passwddata->pwname, passwddata->uid, passwddata->passwd, passwddata->passwd_salt,
                            passwddata->pwfailed, passwddata->pwage);
                    fputs(str, fp);
                    fclose(fp);
                }
            }

		}

		printf("Login Incorrect \n");
	}
	return 0;
}
