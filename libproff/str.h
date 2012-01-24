/* $Id: str.h,v 1.2 1999/09/09 07:43:28 proff Exp $
 * $Copyright:$
 */
#ifndef STR_H
#define STR_H

struct strList
{
	struct strList *next;
	struct strList *head;
	char *data;
};

struct strBinList
{
	struct strBinList *right;
	struct strBinList *left;
	char *data;
};

struct strStack
{
	char *data;
	int used;
	int len;
};

/* we don't do the *x==*y trick, as it doesn't take kindly to functions */
#define strEq(x,y) (strcmp((x), (y)) == 0)
#define strnEq(x,y,z) (strncmp((x), (y), (z)) == 0)
#ifdef HAVE_STRCASECMP
#  define strCaseEq(x,y) (strcasecmp((x), (y)) == 0)
#  define strnCaseEq(x,y,z) (strncasecmp((x), (y), (z)) == 0)
#endif

#include "str.ext"

#endif /* STR_H */

