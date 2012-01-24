#include <unistd.h>
#include <string.h>
#include <err.h>
#include <sys/types.h>

#include "maru.h"
#include "assert.h"
#include "common.h"

#include "block.h"

EXPORT bool maruBlockIoRaw(maruReq *req)
{
    int len = 0;
    maruInstance *i = req->aspect->instance;
    off_t pos = req->block * req->blockSize;
    
    if (i->extent_pos != pos)
	{
	    off_t lpos = lseek(i->extent_fd, pos, SEEK_SET);
	    if (lpos != pos)
	        return FALSE;
	    i->extent_pos = pos;
	}
    switch (req->op)
	{
	case MR_READ:
	    len = read(i->extent_fd, req->data, req->blockSize);
	    break;
	case MR_WRITE:
	    len = write(i->extent_fd, req->data, req->blockSize);
	    break;
	default:
	    NOTREACHED;
	}
    if (len > 0)
	i->extent_pos += len;
    return (len == req->blockSize);
}

static bool
check_req(maruReq *req)
{
    if (req->block >= req->aspect->instance->blocks)
	{
	    warnx("request for block %d lays outside of extent (%d blocks)", req->block,
		  req->aspect->instance->blocks);
	    return FALSE;
	}
    else
	{
	    return TRUE;
	}
}

EXPORT bool maruBlockIoReadZeros(maruReq *req)
{
    if (!check_req(req))
	return FALSE;
    memset(req->data, 0, req->blockSize);
    return TRUE;
}

EXPORT bool maruBlockIoWriteNothing(maruReq *req)
{
    if (!check_req(req))
	return FALSE;
    return TRUE;
}

EXPORT bool maruBlockIo(maruReq *req)
{
    if (!check_req(req))
	return FALSE;
    switch (req->op)
	{
	case MR_READ:
	    if (!maruBlockIoRaw(req))
		return FALSE;
	    maruEncryptBlock(req->aspect, req->data, req->data, req->blockSize,
			     req->block, MCD_DECRYPT);
	    return TRUE;
	case MR_WRITE:
	    maruEncryptBlock(req->aspect, req->data, req->data, req->blockSize,
			     req->block, MCD_ENCRYPT);
	    return maruBlockIoRaw(req);
	default:
	    NOTREACHED;
	}
    return FALSE;
}
