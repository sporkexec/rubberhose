/* $Id: confused_runtime.c,v 1.2 1999/09/09 07:43:23 proff Exp $
 * $Copyright:$
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libproff.h>

#include "conf.h"

EXPORT char *confused (FILE *fin, char *terminator, struct confused_idx *con_idx)
{
#define BAD(x) {msg=(x); goto bad;}
    char line[1024] = "";
    char s1[256], s2_buf[256], *s2 = s2_buf;
    char *msg;
    int n = 0;
    int l;
    
    for (n = 0; fgets (line, sizeof line, fin); n++)
	{
	    struct confused_idx *idx = con_idx;
	    strStripLeftRight (line);
	    if (*line == '#' || !*line)
		continue;
		if (strCaseEq (line, terminator))
		    break;
		*s1 = *s2 = '\0';
		if (sscanf (line, "%255s %255[^\n]", s1, s2) != 2)
		    BAD ("need at least one argument")
			for (idx = con_idx; idx->name; idx++)
				if (strCaseEq (idx->name, s1))
				    goto good;
		BAD ("variable used is not known");
	good:
		strStripLeftRight (s2);
		l = strlen (s2);
		if (*s2 == '"' && s2[l - 1] == '"')
		    s2++[l - 1] = '\0';
		switch (idx->type)
		    {
		    case cf_string:
			*(char **) idx->data = xstrdup (s2);
			break;
		    case cf_bool:
			if (strCaseEq (s2, "yes") ||
			    strCaseEq (s2, "true") ||
			    strCaseEq (s2, "1") ||
			    strCaseEq (s2, "one") ||
			    strCaseEq (s2, "on"))
			    *(bool *) idx->data = 1;
			else if (strCaseEq (s2, "no") ||
				 strCaseEq (s2, "false") ||
				 strCaseEq (s2, "0") ||
				 strCaseEq (s2, "zero") ||
				 strCaseEq (s2, "none") ||
				 strCaseEq (s2, "off"))
			    *(bool *) idx->data = 0;
			else
			    BAD ("boolean required (yes, true, 1, one, on) or (no, false, 0, zero, one, off)");
			break;
		    case cf_int:
			if (!strKToi(s2, (int *)idx->data))
			    BAD ("variable requires integer");
			break;
		    case cf_time:
			if ((*(long *) idx->data = nndtoi (s2)) == -1)
			    BAD ("invalid time");
			break;
		    default:
			BAD ("boys in the attic");
			break;
		    }
	}
    if (ferror (fin))
	{
	    BAD ("couldn't read to the end");
	}
    return NULL;
 bad:
	{
	    static char errmsg[1024 + 256];
	    sprintf (errmsg, "%s (%d): %s", msg, n, line);
	    return errmsg;
	}
#undef BAD
}
