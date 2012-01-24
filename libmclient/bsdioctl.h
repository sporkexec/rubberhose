/* $Id: bsdioctl.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
#ifndef BSDIOCTL_H
#define BSDIOCTL_H

#define MARUIOCATTACH	_IOWR('F', 0, maruIOCattach)	/* attach file */
#define MARUIOCDETACH	_IO('F', 1)			/* detach disk */
#define MARUIOCGSET	_IOWR('F', 2, u_long )		/* set global option */
#define MARUIOCGCLEAR	_IOWR('F', 3, u_long )		/* reset --//-- */
#define MARUIOCUSET	_IOWR('F', 4, u_long )		/* set unit option */
#define MARUIOCUCLEAR	_IOWR('F', 5, u_long )		/* reset --//-- */
#define MARUIOCSETKEY	_IOR('F', 6, maruIOCsetkey)	/* setkey */
#define MARUIOCGSTATS	_IOR('F', 7, maruIOCstats)	/* statistics */

#define MARU_LABELS	0x1	/* Use disk(/slice) labels */
#define MARU_FOLLOW	0x2	/* Debug flow in maru driver */
#define MARU_DEBUG	0x4	/* Debug data in maru driver */
#define MARU_IO		0x8	/* Debug I/O in maru driver */
#define MARU_DONTCLUSTER	0x10	/* Don't cluster */

#endif
