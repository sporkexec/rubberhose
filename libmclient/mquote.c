/* $Id: mquote.c,v 1.2 1999/09/09 07:43:24 proff Exp $
 * $Copyright:$
 */

#include <stdlib.h>
#include <time.h>

#include "mquote.h"
#include "quotes.qh"

#define NQUOTES (sizeof(mquotes)/sizeof(*mquotes))

EXPORT char *mquote()
{
    int i;
    srandom(time(NULL));
    i = random()%NQUOTES;
    return mquotes[i];
}
