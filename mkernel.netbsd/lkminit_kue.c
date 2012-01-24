/* $Id: lkminit_kue.c,v 1.2 1999/09/09 07:43:34 proff Exp $
 * $Copyright:$
 */

#include <sys/param.h>
#include <sys/conf.h>		/* bdec_decl etc */
#include <sys/systm.h>	/* FOR LKMENODEV */
#include <sys/exec.h>		/* lkm.h is broken and requires this */
#include <sys/lkm.h>

#include "kue.h"
#include "nbsd_kue.h"

#if NKUE < 1
#  error NKUE < 1. Why bother?
#endif

/* we `should' use MOD_DEV etc, but the MOD_FOO lkm api, is in my view
 * the work of engineering psychopathy, and should be depreciated */

MOD_MISC ("kue");

static int kue_cmaj = 0;

/* we're a full cdev, missing only a few fingers */
cdev_decl(kue);

/* open, close, read, write, ioctl */
#define cdev_kue_init(c,n) { \
	dev_init(c,n,open), dev_init(c,n,close), dev_init(c,n,read), \
	dev_init(c,n,write), dev_init(c,n,ioctl), (dev_type_stop((*))) enodev, \
	0 /* tty */, dev_init(c,n,poll), (dev_type_mmap((*))) enodev }


static struct cdevsw kue_cdevsw = cdev_kue_init(1, kue), kue_cdevsw_old;

static int kue_load()
{
    int i;
    printf("kue: loading\n");
    for (i=0; i<nchrdev; i++)
	if (cdevsw[i].d_open == (dev_type_open((*)))lkmenodev)
	    {
		kue_cmaj = i;
		break;
	    }
    if (kue_cmaj == 0)
	{
	    printf("kue: No free cdevsw slots\n");
	    return ENODEV;
	}
    printf("kue: loading into character device slot %d\n", kue_cmaj);
    kue_cdevsw_old = cdevsw[kue_cmaj];
    cdevsw[kue_cmaj] = kue_cdevsw;
    kueattach(NKUE);
    return 0;
}

static int kue_unload()
{
    
    printf("kue: unloading from cdevsw slot %d\n", kue_cmaj);
    /* we chould just zero out these slots with bdev_notdef() but restoring the slots to
       their original values should survive kernel future-rot a little better */
    cdevsw[kue_cmaj] = kue_cdevsw_old;
    kuedetach();
    kue_cmaj = 0;
    return 0;
}

/* give kue a little action */
static int kue_action(struct lkm_table *lkmtp, int cmd)
{
    int err = 0;
    switch (cmd)
	{
	case LKM_E_LOAD:
	    if (lkmexists(lkmtp))
		err = EEXIST;
	    else
		err = kue_load();
	    break;
	case LKM_E_UNLOAD:
	    err = kue_unload();
	    break;
	case LKM_E_STAT:
	    err = EIO;
	    break;
	}
    return err;
}

int
kue_lkmentry(struct lkm_table *lkmtp, int cmd, int ver)
{
    if (ver != LKM_VERSION)
	return EINVAL;
    DISPATCH(lkmtp, cmd, ver, kue_action, kue_action, kue_action);
}
