/* $Id: psycho_unix.c,v 1.6 2000/05/12 06:45:52 proff Exp $
 * $Copyright:$
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <err.h>
#include <paths.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <limits.h>

#include "libproff.h"
#include "client_common.h"

#include "psycho_unix.h"

#define UPSYCHO "psychoanalysis: "

static int
test_mtab(int level)
{
    char buf[32];
    int fails = 0;
    bzero(buf, sizeof buf);
#ifdef linux
    if (readlink(_PATH_MOUNTED, buf, sizeof buf) != strlen("/proc/mounts") ||
	strncmp(buf, "/proc/mounts", strlen("/proc/mounts")) != 0)
	{
	    warnx(UPSYCHO "\n\
\t%s is not a symbolic link to /proc/mounts.\n\
\tThis is high evil as usage of mount without the -n flag\n\
\twill semi-permanently record which device has been mounted where\n\
\tin this file. Please link this file to /proc/mounts instead like so:\n\
\n\
\t\trm %s\n\
\t\tln -s /proc/mounts %s\n", _PATH_MOUNTED, _PATH_MOUNTED, _PATH_MOUNTED);
            fails++;
	}
    else
	if (a_debug>1)
	    warnx(UPSYCHO "examining \"%s\"... passed", _PATH_MOUNTED);

#else
#  warning mtab privacy test for this platform currently undefined
#endif
    return fails;
}

static int
test_history(int level)
{
    DIR *dir;
    struct dirent *d;
    char *dirpath = getenv("HOME");
    int fails=0;
    
    if (!dirpath)
	dirpath = ".";
    dir = opendir(dirpath);
    if (!dir)
	{
	    warn("unable to opendir(%s)", dirpath);
	    return 1;
	}
    while ((d=readdir(dir)))
	{
	    if (match(".*sh*history*", d->d_name, TRUE, '\0') ||
		match(".history*", d->d_name, TRUE, '\0'))
		{
		    struct stat st;
		    char buf[_POSIX_PATH_MAX];
		    snprintf(buf, sizeof buf, "%s/%s", dirpath, d->d_name);
		    if (stat(buf, &st) == 0 &&
			S_ISREG(st.st_mode))
			{
			    warnx(UPSYCHO "\n\
\tThe file '%s' appears to be\n\
\tkeeping command histories. History files\n\
\tmay leak sensitive information about your interactions\n\
\twith marutukku. Please remove this file\n\
\tand prevent its re-creation. Before continuing.\n\
\tOne way of doing this is:\n\
\t\trm %s\n\
\t\tmkdir %s\n\
\t\tchmod a-w %s\n\
\tAnother is:\n\
\t\trm %s\n\
\t\tln -s /dev/null %s\n",
				  buf,
				  buf,
				  buf,
				  buf,
				  buf,
				  buf);
			    fails++;
			    break;
			}
		}
	}
    closedir(dir);
    if (a_debug>1 && fails<1)
	warnx(UPSYCHO "examining \"%s\"... passed", dirpath);
    return fails;
}

EXPORT int psycho_unix(int level)
{
    return
	test_history(level) +
	test_mtab(level);
}
