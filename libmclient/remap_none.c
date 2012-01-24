/* $Id: remap_none.c,v 1.5 2000/05/08 12:22:30 proff Exp $
 * $Copyright:$
 */

#include "remap_none.h"

EXPORT bool maruRemapNoneMapIO(maruReq *req)
{
    req->block = req->aspect->start + req->block;
    return maruBlockIo(req);
}
