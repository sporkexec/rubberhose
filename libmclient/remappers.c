/* $Id: remappers.c,v 1.8 2000/05/15 08:36:15 proff Exp $
 * $Copyright:$
 */

#include "remappers.h"

#include "remap_none.h"
#include "remap_splice.h"
#include "remap_bmap.h"

EXPORT maruRemapDesc maruRemapTab[] =
{
    {"none",						/* name */
     "No remapping. Multiple aspects may over-write each other", /* txt */
     NULL,						/* size */
     NULL,						/* create */
     NULL,						/* new */
     NULL,						/* addAspect */
     maruRemapNoneMapIO,				/* mapIO */
     NULL,						/* info */
     NULL,						/* sync */
     NULL,						/* releaseAspect */
     NULL,						/* free */
     REMAP_NONE						/* remapType */
     },
    {"splice",						/* name */
     "Divide extent equally among all possible aspects",/* txt */
     NULL,						/* size */
     NULL,						/* create */
     NULL,						/* new */
     NULL,						/* addAspect */
     maruRemapSpliceMapIO,				/* mapIO */
     NULL,						/* info */
     NULL,						/* sync */
     NULL,						/* releaseAspect */
     NULL,						/* free */
     REMAP_SPLICE					/* remapType */
     },
    {"bmap",						/* name */
     "Dynamically distribute blocks to aspects",	/* txt */
     maruRemapBmapSize,					/* size */
     maruRemapBmapCreate,				/* create */
     maruRemapBmapNew,					/* new */
     maruRemapBmapAddAspect,				/* addAspect */
     maruRemapBmapMapIO,				/* mapIO */
     maruRemapBmapInfo,					/* info */
     maruRemapBmapSync,					/* sync */
     maruRemapBmapReleaseAspect,			/* releaseAspect */
     maruRemapBmapFree,					/* free */
     REMAP_BMAP						/* remapType */
     },
    {/*TERMINATOR*/}
};
