/* $Id: mbsdioctl.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
#ifndef BSDIOCTL_H
#define BSDIOCTL_H

#define MARUIOCATTACH	_IOWR('F', 0, maruIOCattach)	/* attach file */
#define MARUIOCDETACH	_IO('F', 1)			/* detach extent */
#define MARUIOCGSET	_IOWR('F', 2, u_long )		/* set global option */
#define MARUIOCGCLEAR	_IOWR('F', 3, u_long )		/* reset --//-- */
#define MARUIOCUSET	_IOWR('F', 4, u_long )		/* set unit option */
#define MARUIOCUCLEAR	_IOWR('F', 5, u_long )		/* reset --//-- */
#define MARUIOCSETKEY	_IOW('F', 6, maruIOCsetkey)	/* setkey */
#define MARUIOCCLEARKEY	_IO('F', 7)			/* clear key */
#define MARUIOCGSTATS	_IOR('F', 8, maruIOCstats)	/* statistics */

#define MARU_LABELS	0x1	/* Use disk(/slice) labels */
#define MARU_FOLLOW	0x2	/* Debug flow in maru driver */
#define MARU_DEBUG	0x4	/* Debug data in maru driver */
#define MARU_CLUSTER	0x10	/* cluster */

#endif
