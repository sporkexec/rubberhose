/* $Id: str.c,v 1.5 2000/05/04 22:32:30 proff Exp $
 * $Copyright:$
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libproff.h"

#define TRUE 1
#define FALSE 0


EXPORT char *xstrdup (char *s)
{
    void *p;
#ifndef HAVE_STRDUP
    int len;
#endif
#ifdef HAVE_STRDUP
    p = strdup(s);
#else
    p = xmalloc((len=strlen(s)+1));
    memcpy(p, s, len);
#endif
    return p;
}

EXPORT int strExchange (char *s, char c1, char c2)
{
	char *head = s;
	for (; *s; s++)
		if (*s == c1)
			*s = c2;
	return s - head;
}

EXPORT int strLower (char *s)
{
	char *head = s;
	for (; *s; s++)
		*s = tolower (*s);
	return s - head;
}

EXPORT int strUpper (char *s)
{
	char *head = s;
	for (; *s; s++)
		*s = toupper (*s);
	return s - head;
}

/* start is a \0 terminated list of starting characters
 * end is a \0 terminated list of ending characters
 * 
 * the string stored in buf does not include the starting or ending terminators
 * but is null terminated.
 */

EXPORT int strSnip (char *s, int len, char *start, char *end, char *buf, int blen)
{
	int n = 0;
	char *endp;
	for (endp = s+len; s<endp; s++)
	{
		char *p = start;
		while (*p)
		{
			if (*s == *p++)
				goto hit;
		}
	}
	goto ret;
hit:
	for (;s<endp;s++, n++)
	{
		char *p = end;
		while (*p)
		{
			if (s[n] == *p++)
				goto ret;
		}
		*buf++=*s;
	}
ret:
	buf[n] = '\0';
	return n;
}

/* gcc has strcmp built-in (fast) so we use macros if we can. */

#ifndef HAVE_STRCASECMP
EXPORT  int strCaseEq (char *s, char *s2)
{
	do
	{
		if (tolower (*s) != tolower (*s2))
			return FALSE;
	} while (*s++ && *s2++);
	return TRUE;
}

EXPORT int strnCaseEq (char *s, char *s2, int n)
{
	do
	{
		if (tolower (*s) != tolower (*s2))
			return FALSE;
	} while (--n<0);
	return TRUE;
}

EXPORT int strcasecmp (char *s, char *s2)
{
	do
	{
		char c1=tolower(*s);
		char c2=tolower(*s2);
		if (c1>c2)
			return 1;
		if (c1<c2)
			return -1;
	} while (*s++ && *s2++);
	return 0;
}

EXPORT int strncasecmp (char *s, char *s2, int n)
{
	do
	{
		char c1=tolower(*s);
		char c2=tolower(*s2);
		if (c1>c2)
			return 1;
		if (c1<c2)
			return -1;
	} while (--n);
	return 0;
}
#endif

#ifndef HAVE_STRCASESTR
EXPORT char *strcasestr (char *s, char *find)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != 0) {
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == 0)
					return NULL;
			} while (sc != c);
		} while (!strnCaseEq(s, find, len));
		s--;
	}
	return (char *)s;
}
#endif

#ifndef HAVE_STRNCASESTR
EXPORT char *strncasestr (char *s, char *find, int slen)
{
	char c, sc;
	size_t len;
	char *send = s+slen;

	if ((c = *find++) != 0) {
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == 0 || s>=send)
					return NULL;
			} while (sc != c);
		} while (!strnCaseEq(s, find, len));
		s--;
	}
	return ((char *)s);
}
#endif

EXPORT int strStripLeftRight (char *s)
{
	char *p;
	int n;
	
	for (p = s; *p; p++)
		if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')
			continue;
		else
			break;
	if (p!=s)
		strcpy (s, p);
	n = strlen (s);
	if (*p)
	{
		for (p = s + n - 1; p >= s && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t'); p--) ;
		*(p + 1) = '\0';
		return p - s + 1;
	}
	return n;
}

EXPORT int strStripEOL (char *s)
{
	char *head = s;
	for (; *s; s++)
		if (*s == '\r' || *s == '\n')
		{
			*s = '\0';
			break;
		}
	return s - head;
}

/*
 * as above, but n = size of string
 */

EXPORT int strnStripEOL (char *s, int n)
{
	n--;
	while (n>=0 && (s[n] == '\r' || s[n] == '\n'))
		s[n--]='\0';
	return n+1;
}


EXPORT int strMakeEOLn (char *s)
{
	char *head = s;
	for (;; s++)
		if (!*s || *s == '\r')
		{
			*s++ = '\n';
			*s = '\0';
			break;
		}
	return s - head;
}

EXPORT int strMakeEOLrn (char *s)
{
	char *head = s;
	for (;; s++)
		if (!*s || *s == '\n' || *s == '\r')
		{
			*s++ = '\r';
			*s++ = '\n';
			*s = '\0';
			break;
		}
	return s - head;
}

EXPORT unsigned long strHash (unsigned long h, char *s)
{
	int n;
	for (n = 0; s[n]; n++)
		h = (((h << 5) | (h >> (32 - 5))) ^ (s[n] & 0xff) ^ n) & 0xffffffff;
	return h;
}

#if 0 /* marutukku doesn't have a Smalloc yet */

EXPORT struct strList * strListAdd (struct strList *l, char *s)
{
	if (l)
	{
		l->next = (struct strList *) Smalloc (sizeof *l);
		l->next->head = l->head;
		l = l->next;
	} else
	{
		l = (struct strList *) Smalloc (sizeof *l);
		l->head = l;
	}
	l->next = NULL;
	l->data = xstrdup (s);
	return l;
}

EXPORT void strListFree (struct strList *l)
{
	l = l->head;
	while (l)
	{
		struct strList *t = l;
		t = l;
		l = l->next;
		free (t->data);
		free (t);
	}
}

#endif /* 0 */

#if 0
EXPORT struct strList *strBinListAdd (struct strBinList *l, char *s)
{
	if (l)
	{
		l->next = (struct strList *) Smalloc (sizeof *l);
		l->next->head = l->head;
		l = l->next;
	} else
	{
		l = (struct strList *) Smalloc (sizeof *l);
		l->head = l;
	}
	l->next = NULL;
	l->data = xstrdup (s);
	return l;
}

EXPORT void strBinListFree (struct strBinList *l)
{
	l = l->head;
	while (l)
	{
		struct strList *t = l;
		t = l;
		l = l->next;
		free (t->data);
		free (t);
	}
}
#endif

#if 0 /* not used in marutukku yet */

#define STRSTACK_BLOCK_SIZE 4096 /* page size divisible */

/*
 * l->used includes the terminating null
 */

EXPORT struct strStack *strStackAdd (struct strStack *l, char *s)
{
	int len;
	len = strlen (s);
	if (!l)
	{
		l = Smalloc (sizeof *l);
		l->used = 1; /* the nil */
		l->len = len + len%STRSTACK_BLOCK_SIZE;
		l->data = Smalloc(l->len);
		goto ret;
	}
	if (l->used + len > l->len)
	{
		l->len += len;
		l->len += l->len%STRSTACK_BLOCK_SIZE;
		l->data = Srealloc (l->data, l->len);
	}
	memcpy (l->data + l->used - 1, s, len+1);
ret:
	l->used += len;
	return l;
}

EXPORT struct strStack *strnStackAdd (struct strStack *l, char *s, int len)
{
	if (!l)
	{
		l = Smalloc (sizeof *l);
		l->used = 1; /* the nil */
		l->len = len + len%STRSTACK_BLOCK_SIZE;
		l->data = Smalloc (l->len);
	}
	if (l->used + len > l->len)
	{
		l->len += len;
		l->len += l->len%STRSTACK_BLOCK_SIZE;
		l->data = Srealloc (l->data, l->len);
	}
	memcpy (l->data + l->used - 1, s, len);
	l->used += len;
	l->data[l->used-1] = '\0';
	return l;
}

EXPORT void strStackFree (struct strStack *l)
{
	free (l->data);
	free (l);
}

EXPORT void strStackTrim (struct strStack *l)
{
	Srealloc (l->data, l->used);
}
#endif /* 0 */


/*
 * no negatives, -1 is error, must have at least one digit, skips leading white space
 */

EXPORT int strToi (char *s)
{
	int i=0;
	for (;isspace(*s); s++) ;
	if (!isdigit(*s))
		return -1;
	do
	{
		i*=10;
		i+=*s-'0';
	} while (isdigit (*++s));
	return i;
}


EXPORT int strKToi(char *s, int *i)
{
	char *s2=s+strlen(s)-1;
	char c=*s2;
	int k;
	if (sscanf (s, "%d", &k)!=1)
	{
		*i=0;
		return 0;
	}
	*s2='\0';
	switch (c)
	{
	case 'G':
		k*=1024;
	case 'M':
		k*=1024;
	case 'k':
		k*=1024;
	default:
		break;
	}
	*s2 = c;
	*i = k;
	return 1;
}

EXPORT char *conv (double n)
{
	static char buf[128];
	char c;
	if (n > 1073741824)
	{
		n /= 1000000000.0;
		c = 'G';
	} else if (n > 1048576.0)
	{
		n /= 1000000.0;
		c = 'M';
	} else if (n > 1024.0)
	{
		n /= 1000.0;
		c = 'k';
	} else
	{
		sprintf (buf, "%.0fb", n);
		return buf;
	}
	sprintf (buf, "%.2f%c", n, c);
	return buf;
}


EXPORT int strToVec(char *p, char **cp, int cpnum)
{
    int argc=0;
    for (;argc < cpnum;)
	{
	    for (; *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'; *p++ = '\0');
	    if (!*p)
		break;
	    cp[argc++]=p++;
	    while (*p != ' ' && *p && *p != '\t' && *p != '\n' && *p != '\r')
		p++;
	    if (!*p)
		break;
	    *p++ = '\0';
	}
    cp[argc] = NULL;
    return argc;
}

EXPORT int hexToBin(char *in, char *out, int len)
{
    int n;
    if (in[0] == '0' && (in[1] == 'x' || in[1] == 'X'))
	in+=2;
    for (n=0; n<len && in[n/2] && in[n/2+1]; n++)
	{
	    char t[3];
	    int i;
	    t[0] = in[n/2];
	    t[1] = in[n/2+1];
	    t[2] = '\0';
	    if (sscanf(t, "%x", &i)!=1)
		return n;
	    if (i>255)
		return n;
	    out[n]=i;
	}
    return n;
}
