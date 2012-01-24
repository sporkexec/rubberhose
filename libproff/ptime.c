/* $Id: ptime.c,v 1.1 1999/09/09 08:06:54 proff Exp $
 * $Copyright:$
 */

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#include "libproff.h"

/*
 * returns time in seconds of 100y10M2w6d7h10m8s etc
 * -1 == error
 */

#define MINUTE (60)
#define HOUR (MINUTE*60)
#define DAY (HOUR*24)
#define WEEK (DAY*7)
#define YEAR (DAY*365 + DAY/4)
#define MONTH (YEAR/12)

EXPORT long nndtoi (char *s)
{
	long rv = 0;
	long nv;
	int ns, nd;
	char c = 0;
	int s_len = strlen (s);
	char *digits = xmalloc (s_len + 1);
	for (nd = ns = 0; ns <= s_len; ns++)
	{
		c = s[ns];
		if (c >= '0' && c <= '9')
		{
			digits[nd++] = s[ns];
			continue;
		}
		digits[nd] = '\0';
		if (!digits[0] || (sscanf (digits, "%ld", &nv) != 1))
			goto err;
		switch (c)
		{
		case 'y':
			nv *= YEAR;
			break;
		case 'M':
			nv *= MONTH;
			break;
		case 'w':
			nv *= WEEK;
			break;
		case 'd':
			nv *= DAY;
			break;
		case 'h':
			nv *= HOUR;
			break;
		case 'm':
		case '\0':
			nv *= MINUTE;
			break;
		case 's':
			break;
		default:
			goto err;
		}
		rv += nv;
		if (!c || !s[ns + 1])
			break;
		nd = 0;
	}
	free (digits);
	return rv;
      err:
	free (digits);
	return -1;
}

/* reverse of above.. but we don't do [M]onths */

EXPORT char *nnitod (long id)
{
	static char rv[80];
	char tmp[80];
	if (id < 0)
		strcpy (rv, "-");
	else
		*rv = 0;
	id = labs (id);
	if (id > YEAR)
	{
		sprintf (tmp, "%ldd", id / (YEAR));
		strcat (rv, tmp);
		if (!(id % YEAR))
			return rv;
	}
	if ((id %= YEAR) / DAY)
	{
		sprintf (tmp, "%ldd", id / (DAY));
		strcat (rv, tmp);
		if (!(id % DAY))
			return rv;
	}
	if ((id %= DAY) / HOUR)
	{
		sprintf (tmp, "%ldh", id / HOUR);
		strcat (rv, tmp);
		if (!(id % HOUR))
			return rv;
	}
	if ((id %= HOUR) / MINUTE)
	{
		sprintf (tmp, "%ldm", id / MINUTE);
		strcat (rv, tmp);
		if (!(id % MINUTE))
			return rv;
	}
	sprintf (tmp, "%lds", id % MINUTE);
	strcat (rv, tmp);
	return rv;
}
