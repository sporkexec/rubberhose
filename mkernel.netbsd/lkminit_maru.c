/* $Id: lkminit_maru.c,v 1.2 1999/09/09 07:43:34 proff Exp $
 * $Copyright:$
 */

#include <sys/param.h>
#include <sys/conf.h>		/* bdec_decl etc */
#include <sys/systm.h>	/* FOR LKMENODEV */
#include <sys/exec.h>		/* lkm.h is broken and requires this */
#include <sys/lkm.h>

#include "nbsd_maru.h"

#define NMARU 8

#if NMARU < 1
#  error NMARU < 1. Why bother?
#endif

/* we `should' use MOD_DEV etc, but the MOD_FOO lkm api, is in my view
 * the work of engineering psychopathy, and should be depreciated */

MOD_MISC ("maru");

static int maru_bmaj = 0;
static int maru_cmaj = 0;

cdev_decl(maru);
bdev_decl(maru);

static struct bdevsw maru_bdevsw = bdev_disk_init(1, maru), maru_bdevsw_old;
static struct cdevsw maru_cdevsw = cdev_disk_init(1, maru), maru_cdevsw_old;

static int maru_load()
{
    int i;
    printf("maru: loading\n");
    for (i=0; i<nblkdev; i++)
	if (bdevsw[i].d_open == (dev_type_open((*)))lkmenodev)
	    {
		maru_bmaj = i;
		break;
	    }
    if (maru_bmaj == 0)
	{
	    printf("maru: No free bdevsw slots\n");
	    return ENODEV;
	}
    for (i=0; i<nchrdev; i++)
	if (cdevsw[i].d_open == (dev_type_open((*)))lkmenodev)
	    {
		maru_cmaj = i;
		break;
	    }
    if (maru_cmaj == 0)
	{
	    printf("maru: No free cdevsw slots\n");
	    return ENODEV;
	}
    printf("maru: loading into block/character device slots %d/%d\n", maru_bmaj, maru_cmaj);

    maru_bdevsw_old = bdevsw[maru_bmaj];
    bdevsw[maru_bmaj] = maru_bdevsw;
    maru_cdevsw_old = cdevsw[maru_cmaj];
    cdevsw[maru_cmaj] = maru_cdevsw;
    maruattach(NMARU);
    return 0;
}

static int maru_unload()
{
    
    printf("maru: unloading from cdevsw slot %d\n", maru_cmaj);
    /* we chould just zero out these slots with bdev_notdef() but restoring the slots to
       their original values should survive kernel future-rot a little better */
    bdevsw[maru_bmaj] = maru_bdevsw_old;
    cdevsw[maru_cmaj] = maru_cdevsw_old;
    marudetach();
    maru_bmaj = 0;
    maru_cmaj = 0;
    return 0;
}
 
/* give maru a little action */
static int maru_action(struct lkm_table *lkmtp, int cmd)
{
    int err = 0;
    switch (cmd)
	{
	case LKM_E_LOAD:
	    if (lkmexists(lkmtp))
		err = EEXIST;
	    else
		err = maru_load();
	    break;
	case LKM_E_UNLOAD:
	    err = maru_unload();
	    break;
	case LKM_E_STAT:
	    err = EIO;
	    break;
	}
    return err;
}

int
maru_lkmentry(struct lkm_table *lkmtp, int cmd, int ver)
{
    if (ver != LKM_VERSION)
	return EINVAL;
    DISPATCH(lkmtp, cmd, ver, maru_action, maru_action, maru_action);
}
