/* $Id: remap_splice.c,v 1.3 2000/05/02 20:06:33 proff Exp $
 * $Copyright:$
 */

#include <err.h>

#include "remap_splice.h"

EXPORT bool maruRemapSpliceMapIO(maruReq *req)
{
    maruAspect *a = req->aspect;
    maruInstance *i = a->instance;
    if (req->block > (i->blocks / i->aspects))
	{
	    warnx("maruRemapSpliceMapIO(): request for block %d exceeds aspect splice limit", req->block);
	    return FALSE;
	}
    req->block = a->aspect_num * (i->blocks / i->aspects) + req->block;
    return maruBlockIo(req);
}
