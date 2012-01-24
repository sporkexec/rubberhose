/* $Id: maru_bsd_ioctl.h,v 1.3 2000/08/17 14:46:27 ralphcvs Exp $
 * $Copyright:$
 */
#ifndef MARUBSDIOCTL_H
#define MARUBSDIOCTL_H

struct maru_ioc_attach
{
    u_int ma_kue_fd;
    u_int ma_aspect;
    m_u64 ma_size;
};

#define MARUIOCBIND		_IOWR('F', 0, struct maru_ioc_attach)	/* bind aspect to device */
#define MARUIOCUNBIND		_IO('F', 1)				/* unbind aspect from device */
#define MARUIOCPERMISSIVE	_IOWR('F', 3, u_long)		        /* allow non-matching euid for successive
									 * open()s */
#define MARUIOCISBOUND		_IO('F', 4)				/* check whether aspect is bound to device */

/* XXX this #ifdef shouldn't be in here. */
#ifdef linux
#define MARUIOCSETBLKSIZE	_IOWR('F', 2, int)			/* set block size of maru device */
#endif

#define MARU_LABELS	0x1	/* Use disk(/slice) labels */
#define MARU_FOLLOW	0x2	/* Debug flow in maru driver */
#define MARU_DEBUG	0x4	/* Debug data in maru driver */
#define MARU_CLUSTER	0x10	/* cluster */

#endif /* MARUBSDIOCTL_H */
