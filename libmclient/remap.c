/* $Id: remap.c,v 1.6 2000/08/16 13:16:14 proff Exp $
 * $Copyright:$
 */

#include <stdio.h>
#include <string.h>

#include "maru.h"
#include "assert.h"
#include "remap.h"
#include "remappers.h"

EXPORT bool isZero(char *data, int len)
{
    m_u32 *p = (m_u32*)data;
    int num = len/sizeof(*p);
    int step = len/sizeof(void *);
    int n;
    assert(len % sizeof(*p) == 0);
    if (step>0) /* search 8 places for a non zero value */
	{
	    for (n=0; n<num; n+=step)
		if (p[n] != 0)
		    return FALSE;
	}
    /* otherwise lick the whole kaboodle */
    for (n=0; n<num; n++)
	if (p[n] != 0) /* lick */
	    return FALSE;
    return TRUE; /* yum */
}

EXPORT maruRemapDesc *remapLookupStr(char *str)
{
    maruRemapDesc *p;
    for (p=maruRemapTab; p->name; p++)
	if (strcmp(p->name, str) == 0)
	    return p;
    return NULL;
}

EXPORT maruRemapDesc *remapLookupType(maruRemapType type)
{
    maruRemapDesc *p;
    for (p=maruRemapTab; p->name; p++)
	if (p->remapType == type)
	    return p;
    return NULL;
}

EXPORT bool maruRemapIo(maruReq *req)
{
    return req->aspect->instance->remapDesc->mapIO(req);
}
