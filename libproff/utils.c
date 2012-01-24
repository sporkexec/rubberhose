/* $Id: utils.c,v 1.6 2000/06/17 23:22:26 proff Exp $
 * $Copyright:$
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

#ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
#else
#  include <time.h>
#endif

#include "libproff.h"

#ifndef HAVE_USLEEP
EXPORT void usleep (unsigned long useconds)
{
    struct timeval to;
    
    to.tv_sec = useconds / 1000000;
    to.tv_usec = useconds % 1000000;
    select (0, (fd_set *) 0, (fd_set *) 0, (fd_set *) 0, &to);
}
#endif

#ifndef HAVE_DAEMON
EXPORT int daemon(int nochdir, int noclose)
{
    int fd;
    
    if (fork())
	exit(0);
    if(!nochdir)
	chdir("/");
    if(!noclose)
	{
	    for(fd = 0; fd < 256; fd++)
		{
		    close(fd);
		}
	    fd = open("/dev/null", O_RDWR);
	    dup2(0, fd);
	    dup2(1, fd);
	    dup2(2, fd);
	}
#ifdef TIOCNOTTY
    fd = open("/dev/tty", O_RDWR|O_NOCTTY);
    if (fd >= 0)
	{
	    ioctl(fd, TIOCNOTTY, NULL);
	    close(fd);
	}
#endif /* TIOCNOTTY */
#ifdef HAVE_SETSID
    setsid();
#endif /* HAVE_SETSID */
    return 0;
}
#endif


#include <sys/types.h>
#include <fcntl.h>
#ifdef HAVE_MMAP
#  include <sys/mman.h>
#endif

#ifndef HAVE_GETPAGESIZE
# include <sys/param.h>
# ifdef EXEC_PAGESIZE
#  define pagesize EXEC_PAGESIZE
# else
#  ifdef NBPG
#   define pagesize NBPG * CLSIZE
#   ifndef CLSIZE
#    define CLSIZE 1
#   endif
#  else
#   ifdef NBPC
#    define pagesize NBPC
#   else
#    ifdef PAGE_SIZE
#     define pagesize PAGE_SIZE
#    else
#     define pagesize PAGESIZE /* SVR4 */
#    endif
#   endif
#  endif
# endif

EXPORT int getpagesize ()
{
    return pagesize;
}
#endif


EXPORT void *xmalloc(int len)
{
    void *p;
    /* fix: under linux we need to align the length of the memory area we're trying to allocate
     *      to a multiple of the pagesize - otherwise can't lock those memory lock these areas.
     *  --rpw
     */
#ifdef linux
    int psize = getpagesize();
    if (len % psize)
        len += psize - len % psize;
#endif

    p = malloc(len );
    if (!p)
	err(1, "malloc");
    return p;
}

#ifdef HAVE_MLOCK
EXPORT bool f_lockMem = TRUE;
static bool f_lockedAllFutureMem = FALSE;

EXPORT bool lockAllMem(void)
{
    if (!f_lockMem ||
	f_lockedAllFutureMem)
	return TRUE;
    if (mlockall(MCL_FUTURE != 0))
	{
	    warnx("couldn't mlockall(MCL_FUTURE) -- not root?");
	    return FALSE;
	}
    else
	{
	    f_lockedAllFutureMem = TRUE;
	    return TRUE;
	}
}

EXPORT void xmlock(void *p, int len)
{
    static int errs;
    int psize;
    if (!f_lockMem || f_lockedAllFutureMem)
	return;
    psize = getpagesize();
    if (len % psize)
        len += psize - len % psize;

    if (mlock(p, len) != 0 && errs++ == 0)
	warn("couldn't lock %d of data in memory", len);
}

EXPORT void xmunlock(void *p, int len)
{
    int psize;

    if (!f_lockMem || f_lockedAllFutureMem)
	return;

    psize = getpagesize();

    if (len % psize)
        len += psize - len % psize;

    /* important: don't call exit() in here, as we can be called from the atexit() handler */
    munlock(p, len);
}

#endif /* HAVE_MLOCK */
