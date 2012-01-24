#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "maru.h"
#include "kue-api.h"
#include "mkern-api.h"
#include "maru_bsd_ioctl.h"
#include "libmclient.h"
#include "libmclient/block.h"
#include "remap.h"

#include "hosed.h"

#include "block.h"

#define BLOCK_SIZE_MAX			(2 << 16)

#if 0
#define maruBlockIo			maruBlockIoRaw
#endif

/* sets blocksize on aspect device */
EXPORT int maru_set_blocksize(int fd, int blocksize)
{
  static const int blksizes[] = {512, 1024, 2048, 4096, 8192, 0};
  int i;

  for (i = 0; blksizes[i]; i++)
      if (blocksize == blksizes[i]) {
	  if (ioctl(fd, MARUIOCSETBLKSIZE, &blocksize) < 0) {
	      warn("ioctl(MARUIOCSETBLKSIZE, %d)", blocksize);
	      return -1;
	  }
      }
  return 0;
}

EXPORT int maru_handle_chunk(char *data, m_u64 offset, m_u32 length, maruReqOp operation, maruAspect *aspect)
{
    maruReq req;
    m_u32 num_blocks;
    m_u32 align_start, align_end;
    m_u16 blksize;
    int result;
    static char blkbuf[BLOCK_SIZE_MAX];

    if (offset + length > aspect->instance->extent_size)
	return -1;

    blksize       = aspect->instance->blockSize;
    req.blockSize = blksize;
    req.block     = offset / blksize;
    req.aspect    = aspect;
    req.op        = operation;
    req.data	  = data;

    align_start  = offset % blksize;
    align_end    = (offset + length) % blksize;

    num_blocks    = length / blksize;

    /* deal with block boundary alignment issues */
    if (align_start) {
	int fraglen;

	if (length < blksize - align_start) {
	    fraglen = length;
	    align_end = 0;
	}
	else fraglen = blksize - align_start;
	    
	req.op   = MR_READ;
	req.data = blkbuf;
	result   = maruRemapIo(&req);

	if (result < 0) {
	    warn("read failed");
	    return result;
	}

	if (operation == MR_WRITE) {
	    memcpy(blkbuf + align_start, data, fraglen);

	    req.op = MR_WRITE;
	    result = maruRemapIo(&req);
	    if (result < 0) {
		warn("write failed");
		return result;
	    }
	} else
	    memcpy(data, blkbuf + align_start, fraglen);

	req.block++;
	req.data = data + blksize - align_start;
    }

    /* chew the big chunk */
    while(num_blocks--) {
	result = maruRemapIo(&req);
	if (result < 0)
	    return result;
	req.block++;
	req.data += blksize;
    }

    /* deal with block boundary alignment issues */
    if (align_end) {
	req.op   = MR_READ;
	req.data = blkbuf;
	result   = maruRemapIo(&req);

	if (result < 0)
	    return result;
	if (operation == MR_WRITE) {
	    memcpy(blkbuf, data, align_end);

	    req.op = MR_WRITE;
	    result = maruRemapIo(&req);
	    if (result < 0)
		return result;	    
	} else
	    memcpy(data, blkbuf, align_end);
    }

    return length;
}
