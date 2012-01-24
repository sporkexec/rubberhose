/* $Id: mkern-api.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */

#ifndef MKERN_API_H
#define MKERN_API_H

#ifndef linux
#include "maru_bsd_ioctl.h"
#endif

typedef enum
{
    MARU_READ_REQ = 1<<0,
    MARU_READ = 1<<1,
    MARU_WRITE = 1<<2,
    MARU_WRITE_OK = 1<<3,	/* signals to userspace process that the daemon is ready
				 *  to accept further write requests */
    MARU_ERROR = 1<<4           /* signals to kernel module that request royally fucked up */
} maru_msg_type;

#define MARU_ALIGNMENT		sizeof(void *)
#define MARU_WORDALIGN(x)	(((x)+(MARU_ALIGNMENT-1))&~(MARU_ALIGNMENT-1))
#define MARU_HLEN		MARU_WORDALIGN(sizeof(struct maru_message))

struct maru_message
{
    m_u32 mm_flags;
    m_u32 mm_len;
    m_u32 mm_id;
    m_u32 mm_aspect;
    m_u64 mm_offset;
};

#endif /* MKERN_API_H */
