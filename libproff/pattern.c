/* $Id: pattern.c,v 1.2 1999/09/09 07:43:27 proff Exp $
 * $Copyright:$
 */
/* 
 *  Do shell-style pattern matching for ?, \, [], and * characters.
 *  Might not be robust in face of malformed patterns; e.g., "foo[a-"
 *  could cause a segmentation violation.  It is 8bit clean.
 *
 *  Written by Rich $alz, mirror!rs, Wed Nov 26 19:03:17 EST 1986.
 *  Rich $alz is now <rsalz@osf.org>.
 *  April, 1991:  Replaced mutually-recursive calls with in-line code
 *  for the star character.
 *  March, 1996: Added some minor general case optimisations, and those
 *  necessary for 1996 arch/compilers and specified terminator's
 *  - Julian Assange <proff@suburbia.net>
 *  
 *  Special thanks to Lars Mathiesen <thorinn@diku.dk> for the ABORT code.
 *  This can greatly speed up failing wildcard patterns.  For example:
 *      pattern: -*-*-*-*-*-*-12-*-*-*-m-*-*-*
 *      text 1:  -adobe-courier-bold-o-normal--12-120-75-75-m-70-iso8859-1
 *      text 2:  -adobe-courier-bold-o-normal--12-120-75-75-X-70-iso8859-1
 *  Text 1 matches with 51 calls, while text 2 fails with 54 calls.  Without
 *  the ABORT code, it takes 22310 calls to fail.  Ugh.  The following
 *  explanation is from Lars:
 *  The precondition that must be fulfilled is that DoMatch will consume
 *  at least one character in text.  This is true if *p is neither '*' nor
 *  '\0'.)  The last return has ABORT instead of FALSE to avoid quadratic
 *  behaviour in cases like pattern "*a*b*c*d" with text "abcxxxxx".  With
 *  FALSE, each star-loop has to run to the end of the text; with ABORT
 *  only the last one does.
 *
 *  Once the control of one instance of DoMatch enters the star-loop, that
 *  instance will return either TRUE or ABORT, and any calling instance
 *  will therefore return immediately after (without calling recursively
 *  again).  In effect, only one star-loop is ever active.  It would be
 *  possible to modify the code to maintain this context explicitly,
 *  eliminating all recursive calls at the cost of some complication and
 *  loss of clarity (and the ABORT stuff seems to be unclear enough by
 *  itself).  I think it would be unwise to try to get this into a
 *  released version unless you have a good test data base to try it out
 *  on.
 */

#include "libproff.h"
#include <string.h>
#include <ctype.h>

#define TRUE			1
#define FALSE			0
#define ABORT			-1

/* What character marks an inverted character class? */
#define NEGATE_CLASS		'^'
/* Is "*" a common pattern? */
/* Do tar(1) matching rules, which ignore a trailing slash? */
#undef MATCH_TAR_PATTERN

/*
 *  Match text and p, return TRUE, FALSE, or ABORT.
 */
static int domatch (unsigned char *text, unsigned char *p, bool f_case, unsigned char eol)
{
	unsigned char last;
	bool matched;
	bool reverse;

	for (; *p; text++, p++)
	{
		if ((!*text || *text == eol) && *p != '*')
			return ABORT;
		switch (*p)
		{
		case '\\':
			/* Literal match with following character. */
			p++;
			/* FALLTHROUGH */
		default:
			if ((f_case && (tolower (*text) != tolower(*p))) ||
			    *text != *p)
				return FALSE;
			continue;
		case '?':
			/* Match anything. */
			continue;
		case '*':
			while (*++p == '*')
				/* Consecutive stars act just like one. */
				continue;
			if (*p == '\0')
				/* Trailing star matches everything. */
				return TRUE;
			while (*text)
				if ((matched = domatch (text++, p, f_case, eol)) != FALSE)
					return matched;
			return ABORT;
		case '[':
			reverse = p[1] == NEGATE_CLASS ? TRUE : FALSE;
			if (reverse)
				/* Inverted character class. */
				p++;
			matched = FALSE;
			if (p[1] == ']' || p[1] == '-')
				if (*++p == *text)
					matched = TRUE;
			for (last = *p; *++p && *p != ']'; last = *p)
				/* This next line requires a good C compiler. */
				if (*p == '-' && p[1] != ']'
				    ? *text <= *++p && *text >= last : *text == *p)
					matched = TRUE;
			if (matched == reverse)
				return FALSE;
		}
	}

#ifdef	MATCH_TAR_PATTERN
	if (*text == '/')
		return TRUE;
#endif /* MATCH_TAR_ATTERN */
	return *text == '\0' || *text == eol;
}

/* text, pattern. case is significant  */

EXPORT unsigned char match (char *p, char *text, int f_case, char eol)
{
	if (*p == '*')
	{
		if (!p[1])
			return TRUE;
	} else
	{
		if (*p != *text && *p != '?')
			return FALSE;
	}
	return domatch ((unsigned char *) text, (unsigned char *) p, (bool)f_case, (unsigned char )eol) == TRUE;
}

EXPORT unsigned char ispattern (char *p)
{
	if (strcspn(p, "*[]?")==strlen(p))
		return FALSE;
	else
		return TRUE;
}
