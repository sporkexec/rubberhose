/* $Id: kue_bsd_ioctl.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
#ifndef KUEBSDIOCTL_H
#define KUEBSDIOCTL_H

#include <sys/ioccom.h>

#ifdef _KERNEL
struct kue_kapi;

struct kue_kapi /* non opaque part of kue_softc */
{
    int (*ka_read2_hook)(void *p, int len, struct uio *uio);	/* hook: called immediately after writing kc_data */
    int (*ka_free_hook)(void *p, int len);			/* hook: called on error / exit */
    int (*ka_write_hook)(struct kue_kapi *kapi, int len, struct uio *uio);/* hook: deliver data */
    int (*ka_inject)(struct kue_kapi *kapi, void *p, int len);		/* inject onto read queue */
    void (*ka_shutdown)(struct kue_kapi *kapi);		/* shutdown */
    void *ka_sc;						/* opaque backpointer to kue_softc */
};

struct kue_funcs
{
};

#define KUEIOCGKAPI	_IOR('F', 0, struct kue_kapi *)	/* pointer to kernel api */
#endif /* _KERNEL */

#endif /* KUEBSDIOCTL_H */
