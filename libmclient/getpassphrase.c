/* $Id: getpassphrase.c,v 1.6 2000/05/04 22:32:04 proff Exp $
 * $Copyright:$
 */
#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/termios.h>

#ifdef linux
#ifndef TCSASOFT
#define TCSASOFT 0
#endif /* TCSASOFT */
#endif /* linux */

#include "maru_types.h"
#include "getpassphrase.h"

static	RETSIGTYPE *ointhandler, *oquithandler, *otstphandler, *oconthandler;
static	struct termios oterm, term;
static	int fd;

static	RETSIGTYPE
sighandler(int signo)
{
    /* restore tty state */
    tcsetattr(fd, TCSAFLUSH|TCSASOFT, &oterm);
    
    /* restore old sig handlers */
    signal(SIGINT, ointhandler);
    signal(SIGQUIT, oquithandler);
    signal(SIGTSTP, otstphandler);
    
    /* resend us this signal */
    kill(getpid(), signo);
}

static	RETSIGTYPE
sigconthandler(int signo)
{
    /* re-install our signal handlers */
    ointhandler = signal(SIGINT, sighandler);
    oquithandler = signal(SIGQUIT, sighandler);
    otstphandler = signal(SIGTSTP, sighandler);

    /* get new state */
    tcgetattr(fd, &oterm);
    term = oterm;
    term.c_lflag &= ~ECHO;

    /* turn off echo again */
    tcsetattr(fd, TCSAFLUSH|TCSASOFT, &term);
}

EXPORT int getPassPhrase(char *prompt, maruPass *pass)
{
    char *p;
    int fd = 0;
    char *p0 = pass->data;
    if ((p=getenv("MARU_PASSPHRASE")))
	{
	    strncpy(pass->data, p, sizeof pass->data);
	    return strlen(pass->data);
	}

    /*
     * read and write to /dev/tty if possible; else read from
     * stdin and write to stderr.
     */

    if (isatty(fd))
	{
	    ointhandler = signal(SIGINT, sighandler);
	    oquithandler = signal(SIGQUIT, sighandler);
	    otstphandler = signal(SIGTSTP, sighandler);
	    oconthandler = signal(SIGCONT, sigconthandler);
	    tcgetattr(fd, &oterm);
	    term = oterm;
	    term.c_lflag &= ~ECHO;
	    tcsetattr(fd, TCSAFLUSH|TCSASOFT, &term);
	}
    printf("%s", prompt);
    fflush(stdout);
    for (p = p0; p < p0+sizeof(*pass) && read(fd, p, 1)>0 && *p != '\n'; p++)
	{
	}
    *p = '\0';
    printf("\n");
    fflush(stdout);
    if (isatty(fd))
	{
	    tcsetattr(fd, TCSAFLUSH|TCSASOFT, &oterm);
    
	    /* restore old sig handlers */
	    signal(SIGINT, ointhandler);
	    signal(SIGQUIT, oquithandler);
	    signal(SIGTSTP, otstphandler);
	    signal(SIGCONT, oconthandler);
	}
    return p-p0;
}	    

EXPORT int asGetPassPhrase(int as, char *prompt, maruPass *pass)
{
    char mpass[32];
    char *p;
    int len = sizeof *pass;
    sprintf(mpass, "MARU_PASSPHRASE_%d", as);
    p = getenv(mpass);
    if (p)
	{
	    strncpy (pass->data, p, len);
	    return MIN(strlen(p), len);
	}
    return getPassPhrase(prompt, pass);
}
