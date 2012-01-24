/* $Id: mfreebsd.c,v 1.2 1999/09/09 07:43:32 proff Exp $
 * $Copyright:$
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>

#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/disklabel.h>
#include <sys/diskslice.h>
#include <sys/stat.h>
#include <sys/conf.h>

#include <machine/stdarg.h>
#include <machine/random.h>

#include <miscfs/specfs/specdev.h>

#include "maru.h"

/* this needs to be below maru.h */
#ifdef DEVFS
#  include <sys/devfsext.h>
#endif

#include "common.h"
#include "assert.h"

#include "mbsdioctl.h"
#include "mfreebsd.h"

#ifdef MARU_SSLEAY

/* the below is just a stub for symbol-resolution,
 * this should never be called
 */

EXPORT void realloc(void *p, int len)
{
    panic("maru: realloc() called");
}

/* libkern doesn't have it */

EXPORT void *memset(void *b, int c, int len)
{
    char *p = b;
    if (c == 0)
	{
	    bzero(b, len);
	    return p;
	}
    p = b;
    while (len-->0)
	p[len] = c;
    return b;
}

#endif /* MARU_SSLEAY */

static d_open_t maruopen;
static d_close_t maruclose;
static d_ioctl_t maruioctl;
static d_strategy_t marustrategy;

#define CDEV_MAJOR 83
#define BDEV_MAJOR 24

static struct cdevsw maru_cdevsw;	/* we derive this from the bdevsw entry below */
static struct bdevsw maru_bdevsw =
{
    maruopen,			/* d_open */
    maruclose,			/* d_close */
    marustrategy,		/* d_strategy */
    maruioctl,			/* d_ioctl */
    nodump,			/* d_dump */
    nopsize,			/* d_psize */
    0,				/* d_flags */
    "maru",			/* d_name */
    &maru_cdevsw,		/* d_cdev */
    -1				/* d_maj */
};


#define	maruunit(dev) dkunit(dev)
#define	getmarubuf() ((struct buf *)malloc(sizeof(struct buf), M_DEVBUF, M_WAITOK))
#define putmarubuf(bp) free((caddr_t)(bp), M_DEVBUF)

typedef enum {ks_plain, ks_cipher} maruKeyState;
typedef enum {kl_none, kl_strategy, kl_timer} maruKeyLock;

#define MARU_ATTACHED	1
#define MARU_LABLED	2

typedef struct
{
    int m_flags;		/* flags */
    int m_idletime;
    int m_keyLockCount;         /* number of locks */
    int m_lifetime;
    int m_msdrift;              /* msec drift towards plaintext */
    int m_unit;                 /* unit # */
    int m_xorfreq;              /* milliseconds */
    maruIOCstats m_stats;       /* statistics */
    maruAspect *m_aspect;	/* aspect */
    maruKeyLock m_keyLock;      /* in-kernel keys lock status */
    maruKeyState m_keyState;    /* in-kernel keys xor status */
    u_quad_t m_size;            /* size of extent */
    m_u32 m_blocks;             /* size of extent in blocks */
    struct timeval m_tvtouched; /* last key change */
    struct ucred *m_cred;       /* credentials */
    struct vnode *m_vp[MAX_MIRRORS];         /* vnodes */
    time_t m_touched;           /* last r/w */
    int m_ref;                  /* reference count */
    int m_strat_ref;		/* strategy() lock */
    m_u32 m_options;		/* options */
    struct disklabel m_label;	/* geometry information */
    char m_devname[MNAMELEN];	/* device name */
} munit;

static munit *munits[NMARU];

#ifdef DEVFS
static void *maru_devfs [NMARU];
static void *maru_rdevfs [NMARU];
#endif

static m_u32 maru_options = MARU_CLUSTER;

#define IFOPT(opt) if ((maru_options|((maru)? (maru)->m_options: 0)) & (opt))

static void maruiodone (struct buf *bp);
static int marusetcred (munit *maru, struct ucred *cred);
static void marushutdown (int, void *);
static void maruclear (munit *maru, struct proc *p);

EXPORT void *marulcalloc (int len)
{
    void *p;
    p = malloc(len, M_DEVBUF, M_WAITOK);
    if (maru_options & MARU_DEBUG)
	printf("marulcalloc(): len = %d, addr = %p\n", len, p);
    bzero(p, len);
    return p;
}

/* called by assert() in various marutukku libraries */

EXPORT void maruFatal(char *fmt, ...)
{
    int retval;
    va_list ap;
    char buf[2048];
    va_start(ap, fmt);
    retval = kvprintf(fmt, NULL, (void *)buf, 10, ap);
    buf[retval] = '\0';
    va_end(ap);
    panic(buf);
}

static void
maruwipe(void *data, int len)
{
    int n;
    int j;
    u_char *p=data; 
    if (maru_options & MARU_DEBUG)
	printf("maruwipe(data=%p, len = %d)\n", data, len);
    for (j=0; j<10; j++)
        for (n=0; n<len; n++)
	    p[n]^=0xff;
    for (j=0; j<4; j++)
	read_random_unlimited(p, len);
}

static void
marufree_wipe(void *data, int len)
{
    if (maru_options & MARU_DEBUG)
	printf("marufree_wipe(data=%p, len = %d)\n", data, len);
    maruwipe(data, len);
    free(data, M_DEVBUF);
}

static void
marufree_instance(maruAspect *a)
{
    int n;
    if (maru_options & MARU_DEBUG)
	printf("marufree_aspet (a=%p)\n", a);
    for (n=0; n<2; n++)
	{
	    if (a->latticeOpaque[n])
		marufree_wipe (a->latticeOpaque[n], a->latticeCipher->opaque_size);
	}
    if (a->blockOpaque)
	marufree_wipe(a->blockOpaque, a->blockCipher->opaque_size);
    if (a->lattice)
	marufree_wipe(a->lattice, a->lattice_len);
    if (a->lattice)
	marufree_wipe(a->blockIV, a->instance->fsBlockSize);
    marufree_wipe(i, sizeof *i);
}

static void
maruunmount(munit *maru, struct proc *p)
{
    struct mount *mp, *nmp;
    IFOPT(MARU_FOLLOW)
	printf("maruunmount(%p)\n", maru);

    for (mp = mountlist.cqh_last; mp != (void *)&mountlist; mp = nmp)
	{
	    nmp = mp->mnt_list.cqe_prev;
	    IFOPT(MARU_DEBUG)
		printf("maruunmount: mp->mnt_stat.f_mntfromname = %s, maru->m_devname = %s\n",
		       mp->mnt_stat.f_mntfromname, maru->m_devname);
	    if (strncmp(mp->mnt_stat.f_mntfromname, maru->m_devname, MNAMELEN) == 0)
		dounmount(mp, MNT_FORCE, p);
	}
}

static void
maruclose_mirrors(munit *maru, struct proc *p)
{
    int mn;
    for (mn = 0; maru->m_vp[mn] && mn < MAX_MIRRORS; mn++)
	{
	    vn_close (maru->m_vp[mn], FREAD | FWRITE, p->p_ucred, p);
	    VOP_FSYNC (maru->m_vp[mn], maru->m_cred, MNT_NOWAIT, p);
	    maru->m_vp[mn] = NULL;
	}
}


static int
maruclose (dev_t dev, int flags, int mode, struct proc *p)
{
    munit *maru = munits[maruunit (dev)];
    IFOPT (MARU_FOLLOW)
	printf ("maruclose(0x%lx, 0x%x, 0x%x, %p)\n", dev, flags, mode, p);
    if (!maru)
	return (0);
    if (maru->m_ref > 0)
	maru->m_ref--;
    return (0);
}

static void
marulife(void *m)
{
    munit *maru = m;
    IFOPT(MARU_FOLLOW)
	printf ("marulife(m = %p)\n", m);
    if (munits[maru->m_unit])
	maruclear(maru, initproc);
}

static void
maruidle(void *m)
{
    munit *maru = m;
    int since;
    IFOPT(MARU_FOLLOW)
	printf ("maruidle(%p)\n", m);
    if (!munits[maru->m_unit])
	return;
    since = time.tv_sec - maru->m_touched;
    if (since >= maru->m_idletime)
	maruclear(maru, initproc);
    timeout(maruidle, maru, (maru->m_idletime - since)*hz);
}


static void
xor64(void *data, int len)
{
    int n;
    m_u64 *p = data;
    len/=sizeof(*p);
    for (n=0; n<len; n++)
	p[n]^=(m_u64)-1;
}

static void
maruXORkeys(munit *maru)
{
    struct timeval tv;
    maruAspect *a;
    int j;
    IFOPT(MARU_FOLLOW)
	printf ("maruXORkeys(%p)\n", maru);
    a = maru->m_aspect;
    tv = time;
    timevalsub(&tv, &maru->m_tvtouched);
    maru->m_msdrift += (tv.tv_sec*1000 + tv.tv_usec/1000)*(maru->m_keyState == ks_plain)? 1: -1;
    if (maru->m_msdrift > 0 && maru->m_keyState == ks_cipher)
	return;
    if (maru->m_msdrift < 0 && maru->m_keyState == ks_plain)
	return;
    xor64(a->lattice, a->lattice_len);
    xor64(a->blockIV, a->instance->fsBlockSize);
    for (j=0; j<2; j++)
	xor64(a->latticeOpaque[j], a->latticeCipher->opaque_size);
    xor64(a->blockOpaque, sizeof a->blockOpaque);
    maru->m_keyState = (maru->m_keyState == ks_plain)? ks_cipher: ks_plain;
    maru->m_stats.m_keyFlips++;
}

static void
marulock_keys(volatile munit *maru)
{
    int s;
 re:
    s = splbio();
    if (maru->m_keyLock == kl_timer)
	{
	    splx(s);
	    tsleep(maru, PRIBIO, "marukeys", 0);
	    goto re;
	}
    maru->m_keyLockCount++;
    if (maru->m_keyLock != kl_strategy) /* we maybe running concurrently */
	{
	    maru->m_keyLock = kl_strategy;
	    splx(s);
	    if (maru->m_keyState == ks_cipher)
		maruXORkeys(maru);
	}
    else
	splx(s);
}

static void
maruunlock_keys(volatile munit *maru)
{
    int s;
    s = splbio();
    if (--maru->m_keyLockCount == 0)
	maru->m_keyLock = kl_none;
    splx(s);
}

static void
maruKeyTimer(void *m)
{
    volatile munit *maru = m; /* right sematics for volatile ?*/
    int s;
    IFOPT(MARU_FOLLOW)
	printf ("maruXORkey(%p)\n", m);
    if (!munits[maru->m_unit])
	return;
    if (!maru->m_aspect)
	return;
    s = splbio(); /* where is MUTEX() when you need it */
    switch (maru->m_keyLock)
	{
	case kl_none:
	    break;
	case kl_timer:
	case kl_strategy:
	    splx(s);
	    goto end;
	default:
	    panic("maruKeyTimer() default: I'm dazed and confused");
	}
    maru->m_keyLock = kl_timer;
    maru->m_keyLockCount++;
    splx(s);
    maruXORkeys(maru);
    s = splbio();
    maru->m_keyLockCount--;
    if (maru->m_keyLock == kl_strategy)
	{ 
	    splx(s);
	    wakeup(maru);
	}
    else
	{
	    if (maru->m_keyLockCount == 0)
		maru->m_keyLock = kl_none;
	    splx(s);
	}
 end:
    timeout(maruKeyTimer, maru, ((maru->m_xorfreq*hz/1000)>0)? (maru->m_xorfreq*hz)/1000: 1);
}


static void
marulabel(munit *maru)
{
    struct disklabel *l = &maru->m_label;
    l->d_secsize = DEV_BSIZE;
    l->d_nsectors = 32;
    l->d_ntracks = 64;
    l->d_ncylinders = maru->m_blocks / (32 * 64);
    l->d_secpercyl = 32 * 64;
    l->d_sbsize = 8192; /* bogus? */
    l->d_secperunit = l->d_partitions[RAW_PART].p_size = maru->m_blocks;
    l->d_partitions[0].p_size = maru->m_blocks;
    l->d_npartitions = 2;
    l->d_magic = l->d_magic2 = DISKMAGIC;

    maru->m_flags |= MARU_LABLED;
    IFOPT (MARU_DEBUG)
	printf("maru: disk label %d cyls %u size\n", l->d_ncylinders, (m_u32)maru->m_blocks);
}

static int
maruopen (dev_t dev, int flags, int mode, struct proc *p)
{
    int unit = maruunit (dev);
    munit *maru;

    if (unit >= NMARU)
	return (ENOENT);

    maru = munits[unit];
    IFOPT (MARU_FOLLOW)
	printf ("maruopen(0x%lx, 0x%x, 0x%x, %p)\n", dev, flags, mode, p);

    if (!maru)
	{
	    maru = malloc (sizeof *maru, M_DEVBUF, M_WAITOK);
	    if (!maru)
		return (ENOMEM);
	    bzero (maru, sizeof *maru);
	    maru->m_unit = unit;
	    munits[unit] = maru;
	}
    maru->m_ref++;
    return (0);
}

/*
 * this code does I/O calls through the appropriate VOP entry point...
 * unless a swap_pager I/O request is being done.  This strategy (-))
 * allows for coherency with mmap except in the case of paging.  This
 * is necessary, because the VOP calls use lots of memory (and actually
 * are not extremely efficient -- but we want to keep semantics correct),
 * and the pageout daemon gets really unhappy (and so does the rest of the
 * system) when it runs out of memory.
 */
static void
marustrategy (struct buf *bp)
{
    int unit = maruunit (bp->b_dev);
    munit *maru = munits[unit];
    daddr_t bn;
    int error = 0;
    m_32 sz;
    struct uio auio;
    struct iovec aiov;
    int c_blocksize;
    maruAspect *a;
    m_u32 resid;
    m_u32 count;
    int s;

    IFOPT (MARU_FOLLOW)
	printf ("marustrategy(%p): unit %d\n", bp, unit);

    if (!maru || !(maru->m_flags & MARU_ATTACHED))
	{
	    bp->b_error = ENXIO;
	    bp->b_flags |= B_ERROR;
	    biodone (bp);
	    return;
	}
    s = splbio();
/*
    if (maru->m_strat_ref > 0)
	{
	    splx(s);
	    tsleep(&maru->m_strat_ref, PRIBIO, "marustra", 0);
	    s = splbio();
	}
*/
    maru->m_strat_ref++;
    splx(s);
    maru->m_touched = time.tv_sec;
    count = bp->b_bcount;
    a = maru->m_aspect;
  
    if (a)
	{
	    c_blocksize = a->blockCipher->blocksize;
	    if (count % c_blocksize !=0)
		{
		    printf ("maru: b_bcount %d not a multiple of %d\n", count, c_blocksize);
		    bp->b_error = ESPIPE;
		    bp->b_flags |= B_ERROR;
		    biodone (bp);
		    maru->m_strat_ref--;
		    wakeup(&maru->m_strat_ref);
		    return;
		}
	}

    bn = bp->b_blkno;
    sz = howmany (count, DEV_BSIZE);
    bp->b_resid = count;
    if (bn < 0 || bn + sz > maru->m_blocks)
	{
	    if (bn != maru->m_blocks)
		    {
			bp->b_error = EINVAL;
			bp->b_flags |= B_ERROR;
		    }
	    biodone (bp);
	    maru->m_strat_ref--;
	    wakeup(&maru->m_strat_ref);
	    return;
	}
    if (!(bp->b_flags & B_PAGING))
	{
	    int offset;
	    struct uio auiot;
	    struct iovec aiovt;

	    aiov.iov_base = bp->b_data;
	    aiov.iov_len = count;
	    auio.uio_iov = &aiov;
	    auio.uio_iovcnt = 1;
	    /* this breaks reads character device reads that do not begin on block boundaries!
	      * but as there is no bp->b_offset field (as there should be), there isn't anything
	      * we can do about it.
	      */
	    offset = auio.uio_offset = dbtob (bn);
	    auio.uio_segflg = UIO_SYSSPACE;
	    if (bp->b_flags & B_READ)
		auio.uio_rw = UIO_READ;
	    else
		auio.uio_rw = UIO_WRITE;
	    resid = auio.uio_resid = count;
	    IFOPT (MARU_DEBUG)
		printf ("iov_len = %d uio_offset = %d iov_base = %x bufsize = %qd b_kvabase = %x b_kvasize = %d b_npages = %d\n", aiov.iov_len, auio.uio_offset, aiov.iov_base, bp->b_bufsize, bp->b_kvabase, bp->b_kvasize, bp->b_npages);
	    auio.uio_procp = curproc;
	    if (bp->b_flags & B_READ)
		{
		    int mn;
		    struct vnode *vp;
		    u_char *oven = NULL;
		    error = 0;
/*
		    if (I)
			{
			    if (count%I->fsBlockSize !=0)
				{
				    aiov.iov_len
				    oven = malloc(, M_DEVBUF, M_WAITOK);
*/
		    for (mn = 0; (vp=maru->m_vp[mn]) && mn<MAX_MIRRORS; mn++)
			{
			    bool vp_locked;
			    auiot = auio;
			    aiovt = aiov;
			    auiot.uio_iov = &aiovt;
			    
			    if (error)
				printf("marustrategy() hot swapping from mirror %d", mn);
			    if (!VOP_ISLOCKED(vp))
				{
				    vp_locked = TRUE;
				    VOP_LOCK(vp);
				}
			    else
				vp_locked = FALSE;
			    IFOPT (MARU_DEBUG)
				printf("VOP_READ(%p, %p, %d, %p)\n", vp, &auiot, 0, maru->m_cred);
			    error = VOP_READ (vp, &auiot, 0, maru->m_cred);
			    IFOPT (MARU_DEBUG)
				printf("VOP_READ ok\n");
			    if (vp_locked)
				{
				    VOP_UNLOCK(vp);
				}
			    if (error)
				{
				    printf("marustrategy() read error %ld on unit %ld mirror %ld, %ld bytes at offset %d", error, unit, mn, count, offset);
				    maru->m_stats.m_mirror[mn].m_rerr++;
				}
			    else
				break;
			}
		    resid = auiot.uio_resid;
		    if (!error)
			{
			    if (a)
				{
				    int cc = count - resid;
				    int n;
				    if (cc % c_blocksize !=0)
					{
					    int adjust = cc % c_blocksize;
					    printf ("maru: bytes read %d not a multiple of %d, adjusted down by %d\n", cc, c_blocksize, -adjust);
					    cc -= adjust;
					    resid += adjust;
					}
				    marulock_keys(maru);
				    for (n=0; n<cc; n+=a->instance->fsBlockSize)
					{
					    IFOPT (MARU_DEBUG)
						printf("maru: read..crypt(%p %p %p %d %d %d)\n", a, bp->b_data+n, bp->b_data+n, MIN(cc-n, a->instance->fsBlockSize), (offset+n)/a->instance->fsBlockSize, MCD_DECRYPT);
					    maruEncryptBlock(a, bp->b_data+n, bp->b_data+n, MIN(cc-n, a->instance->fsBlockSize), (offset+n)/a->instance->fsBlockSize, MCD_DECRYPT);
					    maru->m_stats.m_decrypt++;
					}
				    maruunlock_keys(maru);
				}
			}
		}
	    else
		{
		    struct vnode *vp;
		    u_char *oven = NULL;
		    int mn;
		    {
			if (a)
			    {
				int n;
				/* we make a private copy of the data, because if we don't we end up
				 * encrypting the overlaying file-systems's write cache data
				 */
				oven = malloc(aiov.iov_len, M_DEVBUF, M_WAITOK);
				if (!oven)
				    {
					error = ENOMEM;
					goto err;
				    }
				if (aiov.iov_len % c_blocksize !=0)
				    {
					int adjust = aiov.iov_len % c_blocksize;
					printf ("maru: write bytes %d not a multiple of %d, adjusted down by %d\n", aiov.iov_len, c_blocksize, adjust);
					aiov.iov_len -= adjust;
				    }
				marulock_keys(maru);
				for (n=0; n<aiov.iov_len; n += a->instance->fsBlockSize)
				    {
					int i;
					i = MIN(aiov.iov_len-n, a->instance->fsBlockSize);
					IFOPT (MARU_DEBUG)
					    printf("maru: write ins %p data %p len %d bn %d\n", a, oven+n, i, (offset+n)/a->instance->fsBlockSize);
					maruEncryptBlock(a, bp->b_data+n, oven+n, i, (offset+n)/a->instance->fsBlockSize, MCD_ENCRYPT);
					maru->m_stats.m_encrypt++;
				    }
				maruunlock_keys(maru);
				aiov.iov_base = oven;
			    }
			
		    }
		    for (mn = 0; (vp=maru->m_vp[mn]) && mn<MAX_MIRRORS; mn++)
			{
			    int e;
			    bool vp_locked;
			    auiot = auio;
			    aiovt = aiov;
			    auiot.uio_iov = &aiovt;
			    if (!VOP_ISLOCKED(vp))
				{
				    vp_locked = TRUE;
				    VOP_LOCK(vp);
				}
			    else
				vp_locked = FALSE;
			    e = VOP_WRITE (vp, &auiot, 0, maru->m_cred);
			    if (vp_locked)
				{
				    VOP_UNLOCK(vp);
				}
			    if (e)
				{
				    error = e;
				    printf("marustrategy() write error %d on unit %d mirror %ld, %d bytes at offset %d", error, unit, mn, count, offset);
				    maru->m_stats.m_mirror[mn].m_werr++;
				    resid = auiot.uio_resid;
				}
			}
		    if (!error)
			resid = auiot.uio_resid;
		    if (oven)
			free(oven, M_DEVBUF);
		err:
		    ;
		}

	    bp->b_resid = resid;

	    if (error)
		bp->b_flags |= B_ERROR;
	    IFOPT (MARU_DEBUG)
		printf ("maru: (near biodone()) iov_len = %d uio_offset = %d uio_resid = %d iov_base = %d\n", aiov.iov_len, auio.uio_offset, resid, aiov.iov_base);
	    biodone (bp);
	}
    else
	{
	    m_32 bsize, resid;
	    off_t byten;
	    int flags;
	    caddr_t addr;
	    struct buf *nbp;

	    nbp = getmarubuf ();
	    byten = dbtob (bn);
	    bsize = maru->m_vp[0]->v_mount->mnt_stat.f_iosize;
	    addr = bp->b_data;
	    flags = bp->b_flags | B_CALL;
	    for (resid = bp->b_resid; resid>0;)
		{
		    struct vnode *vp;
		    daddr_t nbn;
		    int off, s, nra;

		    nra = 0;
		    VOP_LOCK (maru->m_vp[0]);
		    error = VOP_BMAP (maru->m_vp[0], (daddr_t) (byten / bsize),
				      &vp, &nbn, &nra, NULL);
		    VOP_UNLOCK (maru->m_vp[0]);
		    if (error == 0 && nbn == -1)
			error = EIO;

		    IFOPT (MARU_CLUSTER)
			;
		    else
			nra = 0;

		    off = byten % bsize;
		    if (off)
			sz = bsize - off;
		    else
			sz = (1 + nra) * bsize;
		    if (resid < sz)
			sz = resid;

		    if (error)
			{
			    bp->b_resid -= (resid - sz);
			    bp->b_flags |= B_ERROR;
			    biodone (bp);
			    putmarubuf (nbp);
			    maru->m_strat_ref--;
			    wakeup(&maru->m_strat_ref);
			    return;
			}

		    IFOPT (MARU_DEBUG)
			printf (
		    /* XXX no %qx in kernel.  Synthesize it. */
		     "marustrategy: vp %p/%p bn 0x%lx%08lx/0x%lx sz 0x%x\n",
				   maru->m_vp[0], vp, (m_32) (byten >> 32),
				   (m_u32) byten, nbn, sz);

		    nbp->b_flags = flags;
		    nbp->b_bcount = sz;
		    nbp->b_bufsize = sz;
		    nbp->b_error = 0;
		    if (vp->v_type == VBLK || vp->v_type == VCHR)
			nbp->b_dev = vp->v_rdev;
		    else
			nbp->b_dev = NODEV;
		    nbp->b_data = addr;
		    nbp->b_blkno = nbn + btodb (off);
		    nbp->b_proc = bp->b_proc;
		    nbp->b_iodone = maruiodone;
		    nbp->b_vp = vp;
		    nbp->b_rcred = maru->m_cred;	/* XXX crdup? */
		    nbp->b_wcred = maru->m_cred;	/* XXX crdup? */
		    nbp->b_dirtyoff = bp->b_dirtyoff;
		    nbp->b_dirtyend = bp->b_dirtyend;
		    nbp->b_validoff = bp->b_validoff;
		    nbp->b_validend = bp->b_validend;

		    if ((nbp->b_flags & B_READ) == 0)
			nbp->b_vp->v_numoutput++;

		    VOP_STRATEGY (nbp);

		    s = splbio ();
		    while ((nbp->b_flags & B_DONE) == 0)
			{
			    nbp->b_flags |= B_WANTED;
			    tsleep (nbp, PRIBIO, "marupage", 0);
			}
		    splx (s);

		    if (nbp->b_flags & B_ERROR)
			{
			    bp->b_flags |= B_ERROR;
			    bp->b_resid -= (resid - sz);
			    biodone (bp);ru
			    putmarubuf (nbp);
			    maru->m_strat_ref--;
			    wakeup(&maru->m_strat_ref);
			    return;
			}

		    byten += sz;
		    addr += sz;
		    resid -= sz;
		}
	    biodone (bp);
	    putmarubuf (nbp);
	}
    maru->m_strat_ref--;
    wakeup(&maru->m_strat_ref);
}

static void
maruiodone (struct buf *bp)
{
    bp->b_flags |= B_DONE;
    wakeup ((caddr_t) bp);
}

/* ARGSUSED */
static int
maruioctl (dev_t dev, int cmd, caddr_t data, int flag, struct proc *p)
{
    munit *maru = munits[maruunit (dev)];
    int error;
    m_u32 *f;


    IFOPT (MARU_FOLLOW)
	printf ("maruioctl(0x%lx, 0x%x, %p, 0x%x, %p): unit %d\n",
		dev, cmd, data, flag, p, maruunit (dev));

    error = suser (p->p_ucred, &p->p_acflag);
    if (error)
	return (error);
    if (!maru)
	return (ENXIO);
    f = (m_u32 *) data;
    switch (cmd)
	{

	case MARUIOCATTACH:
	    {
		int mn;
		int slen;

		maruIOCattach *m = (maruIOCattach *)data;
		if (maru->m_flags & MARU_ATTACHED)
		    return (EBUSY);
		/*
		 * Always open for read and write.
		 * This is probably bogus, but it lets maru_open()
		 * weed out directories, sockets, etc. so we don't
		 * have to worry about them.
		 */
		
		for (mn=0; m->m_extent[mn] && mn < MAX_MIRRORS; mn++)
		    {
			struct nameidata nd;
			struct vattr vattr;
			NDINIT (&nd, LOOKUP, FOLLOW, UIO_USERSPACE, m->m_extent[mn], p);
			error = vn_open (&nd, FREAD | FWRITE, 0);
			if (error)
			    goto err;
			maru->m_vp[mn] = nd.ni_vp;
			error = VOP_GETATTR (nd.ni_vp, &vattr, p->p_ucred, p);
			VOP_UNLOCK (nd.ni_vp);
			if (error)
			    goto err;
			if (mn == 0)
			    maru->m_size = vattr.va_size;
			else
			    if (maru->m_size != vattr.va_size)
				{
				    printf("maruioctl() MARUATTACH: mirror %d size != mirror 0 size (unit %d)", mn, maru->m_unit);
				    goto err;
				}
			maru->m_stats.m_mirror[mn].m_active = TRUE;
		    }
		if (mn<1)
		    return (EINVAL);
		error = marusetcred (maru, p->p_ucred);
		if (error)
		    goto err;
		error = copyinstr(m->m_dev, &maru->m_devname, MNAMELEN, &slen);
		if (error)
		    goto err;
		maru->m_blocks = maru->m_size/DEV_BSIZE; /* round down */
		m->m_size = maru->m_size;
		marulabel(maru);
		maru->m_flags |= MARU_ATTACHED;
		IFOPT (MARU_FOLLOW)
		    printf ("maruioctl: SET vp %p size %x\n",
			    maru->m_vp[0], (m_u32)maru->m_size);
		break;
	    err:
		maruclose_mirrors(maru, p);
		return (error);
	    }

	case MARUIOCDETACH:
	    if (!maru)
		return (ENXIO);
	    /*
	     * XXX handle i/o in progress.  Return EBUSY, or wait, or
	     * flush the i/o.
	     * XXX handle multiple opens of the device.  Return EBUSY,
	     * or revoke the fd's.
	     * How are these problems handled for removable and failing
	     * hardware devices?
	     */
	    maruclear (maru, p);
	    IFOPT (MARU_FOLLOW)
		printf ("maruioctl: CLRed\n");
	    break;

	case MARUIOCGSET:
	    maru_options |= *f;
	    *f = maru_options;
	    break;

	case MARUIOCGCLEAR:
	    maru_options &= ~(*f);
	    *f = maru_options;
	    break;

	case MARUIOCUSET:
	    if (!maru)
		return (ENXIO);
	    maru->m_options |= *f;
	    *f = maru->m_options;
	    break;

	case MARUIOCUCLEAR:
	    if (!maru)
		return (ENXIO);
	    maru->m_options &= ~(*f);
	    *f = maru->m_options;
	    break;

	case MARUIOCGSTATS:
	    if (!maru)
		return (ENXIO);
	    {
		maruIOCstats *m = (maruIOCstats*)data;
		*m = maru->m_stats;
	    }
	    break;

	case MARUIOCCLEARKEY:
	    if (!maru)
		return (ENXIO);
	    {
		if (maru->m_aspect)
		    {
			maruAspect *a = maru->m_aspect;
			untimeout(marulife, maru);
			untimeout(maruidle, maru);
			untimeout(maruKeyTimer, maru);
			maru->m_aspect = NULL;
			marufree_aspect(a);
		    }
	    }
	    break;

	case MARUIOCSETKEY:
	    if (!maru)
		return (ENXIO);
	    {
		maruIOCsetkey *m = (maruIOCsetkey *)data;
		maruAspect *a;
		maruInstance *i_
		int n;
		IFOPT (MARU_FOLLOW)
		    printf("maruioctl: MARUIOCSETKEY %p on unit %d\n", data, maruunit(dev));
		a = malloc (sizeof *a, M_DEVBUF, M_WAITOK);
		if (!a)
		    {
			maruwipe(m, sizeof *m);
			return (ENOMEM);
		    }
		IFOPT (MARU_DEBUG)
		    printf("maruioctl: MARUIOCSETKEY: 1\n");
		memcpy(a, &m->m_aspect, sizeof *a);
		a->blockCipher = NULL;
		a->latticeCipher = NULL;
		a->latticeOpaque[0] = NULL;
		a->latticeOpaque[1] = NULL;
		a->blockOpaque = NULL;
		a->blockIV = NULL;
		a->lattice = NULL;
		a->latticeCipher  = findCipherType(a->latticeCipherType);
		a->blockCipher = findCipherType(a->blockCipherType);
		IFOPT (MARU_DEBUG)
		    printf("maruioctl: MARUIOCSETKEY: 2\n");
		if (!a->latticeCipher || !a->blockCipher
		    || a->depth > MAX_LATTICE_DEPTH
		    || a->fsBlockSize < a->blockCipher->blocksize
		    || a->lattice_len != MIN(EITHER(a->blockCipher->keylen, MAX_BLOCK_KEY), MAX_BLOCK_KEY) * 2 * a->depth)
		    {
			printf ("maru: MARUIOCSETKEY: invalid cipher/depth/fsBlockSize specified for unit %d (lcipher = %d, bcipher = %d, depth = %d, fsBlockSize %d)\n", maruunit(dev), a->latticeCipherType, a->blockCipherType, a->depth, a->fsBlockSize);
			marufree_wipe(i, sizeof *i);
			maruwipe(m, sizeof *m);
			return (EINVAL);
		    }
		IFOPT (MARU_DEBUG)
		    printf("maruioctl: MARUIOCSETKEY: 3\n");
		IFOPT (MARU_DEBUG)
		    printf("maruioctl: MARUIOCSETKEY: 4\n");
		for (n=0; n<2; n++)
		    {
			if (!(a->latticeOpaque[n] = maruOpaqueInit (a->latticeCipher)))
			    {
				error = ENOMEM;
				goto bad;
			    }
			error = copyin(m->m_instance.latticeOpaque[n],
				       a->latticeOpaque[n],
				       a->latticeCipher->opaque_size);
			if (error)
			    goto bad;
		    }
		IFOPT (MARU_DEBUG)
		    printf("maruioctl: MARUIOCSETKEY: 5\n");
		if (!(a->blockOpaque = maruOpaqueInit (a->blockCipher)))
		    {
			error = ENOMEM;
			goto bad;
		    }
		IFOPT (MARU_DEBUG)
		    printf("maruioctl: MARUIOCSETKEY: 6\n");
		IFOPT (MARU_DEBUG)
		    printf("maruioctl: MARUIOCSETKEY: 7\n");
		error = copyin(m->m_instance.blockOpaque, a->blockOpaque,
			       a->blockCipher->opaque_size);
		IFOPT (MARU_DEBUG)
		    printf("maruioctl: MARUIOCSETKEY: 8\n");
		if (error)
		    goto bad;
		if (!(a->blockIV = malloc (a->fsBlockSize, M_DEVBUF, M_WAITOK)))
		    {
			error = ENOMEM;
			goto bad;
		    }
		error = copyin(m->m_instance.blockIV, a->blockIV,
			       a->fsBlockSize);
		if (error)
		    goto bad;
		if (!(a->lattice = malloc (a->lattice_len, M_DEVBUF, M_WAITOK)))
		    {
			error = ENOMEM;
			goto bad;
		    }
		error = copyin(m->m_instance.lattice, a->lattice,
			       a->lattice_len);
		IFOPT (MARU_DEBUG)
		    printf("maruioctl: MARUIOCSETKEY: 8.1\n");
		if (error)
		    goto bad;
		maru->m_tvtouched = time;
		maru->m_keyState = ks_plain;
		maru->m_lifetime = m->m_lifetime;
		maru->m_idletime = m->m_idletime;
		maru->m_xorfreq = m->m_xorfreq;	
		maruwipe(m, sizeof *m);
		/* don't use m from this point on! */
		maru->m_touched = time.tv_sec;
		if (maru->m_aspect)
		    {
			untimeout(marulife, maru);
			untimeout(maruidle, maru);
			untimeout(maruKeyTimer, maru);
			maru->m_aspect = NULL;
			marufree_aspect(a);
		    }
		maru->m_aspect = a;
		timeout(marulife, maru, maru->m_lifetime*hz);
		timeout(maruidle, maru, maru->m_idletime*hz);
		if (maru->m_xorfreq > 0)
		    timeout(maruKeyTimer, maru, ((maru->m_xorfreq*hz/1000)>0)? (maru->m_xorfreq*hz)/1000: 1);
		break;
	    bad:
		IFOPT (MARU_DEBUG)
		    printf("maruioctl: MARUIOCSETKEY: 9\n");
		marufree_aspect(a);
		maruwipe(m, sizeof *m);
		return (error);
	    }
	    break;
	case DIOCGDINFO:
	    if (!maru)
		return (ENXIO);
	    *(struct disklabel *)data = maru->m_label;
	    break;
	/* we should probably forbid the below but there is a possible
	 * valid case of changing the non-geometry components of the
	 * disk label */
        case DIOCWDINFO:
        case DIOCSDINFO:
	    if (!maru)
		return (ENXIO);
	    return setdisklabel(&maru->m_label, (struct disklabel *)data, 0);
	default:
	    return (ENOTTY);
	}
    return (0);
}

/*
 * Duplicate the current processes' credentials.  Since we are called only
 * as the result of a SET ioctl and only root can do that, any future access
 * to this "disk" is essentially as root.  Note that credentials may change
 * if some other uid can write directly to the mapped file (NFS).
 */
int
marusetcred (munit *maru, struct ucred *cred)
{
    struct uio auio;
    struct iovec aiov;
    char *tmpbuf;
    int error;

    maru->m_cred = crdup (cred);
    tmpbuf = malloc (DEV_BSIZE, M_TEMP, M_WAITOK);

    /* XXX: Horrible kludge to establish credentials for NFS */
    aiov.iov_base = tmpbuf;
    aiov.iov_len = maru->m_blocks;
    auio.uio_iov = &aiov;
    auio.uio_iovcnt = 1;
    auio.uio_offset = 0;
    auio.uio_rw = UIO_READ;
    auio.uio_segflg = UIO_SYSSPACE;
    auio.uio_resid = aiov.iov_len;
    VOP_LOCK (maru->m_vp[0]);
    error = VOP_READ (maru->m_vp[0], &auio, 0, maru->m_cred); /* XXX mirrors on diff nfs maritions? */
    VOP_UNLOCK (maru->m_vp[0]);

    free (tmpbuf, M_TEMP);
    return (error);
}

/* fleabsd has functions for assigning devices but not removing them */

static void
marucdevsw_rm(int maj)
{
    cdevsw[maj] = NULL;
}

static void
marubdevsw_rm(int maj)
{
    bdevsw[maj] = NULL;
}

static void
marushutdown (int howto, void *ignored)
{
    int i;
    marubdevsw_rm(BDEV_MAJOR);
    marucdevsw_rm(CDEV_MAJOR);
    for (i = 0; i < NMARU; i++)
	{
	    if (munits[i])
		maruclear (munits[i], initproc);
#ifdef DEVFS
	    if (maru_devfs[i])
		devfs_remove_dev(maru_devfs[i]);
	    if (maru_rdevfs[i])
		devfs_remove_dev(maru_rdevfs[i]);
#endif
	}
}

static void
maruclear (munit *maru, struct proc *p)
{
    IFOPT (MARU_FOLLOW)
	printf ("maruclear(%p): unit=%d\n", maru, maru->m_unit);
    munits[maru->m_unit] = NULL;
    if (maru->m_ref > 1) /* 1 ref for the open doing the ioctl() */
	printf ("maruclear() warning: reference count = %d\n", maru->m_ref);
    if (maru->m_flags & MARU_ATTACHED)
	{
	    if (maru->m_aspect)
		{
		    untimeout(marulife, maru);
		    untimeout(maruidle, maru);
		    untimeout(maruKeyTimer, maru);
		    marufree_aspect(maru->m_aspect);
		}
	    maruclose_mirrors(maru, p);
	    maruunmount(maru, p);
	}
    if (maru->m_cred)
	crfree (maru->m_cred);
    free(maru, M_DEVBUF);
}

static maru_devsw_installed = 0;

static void
maru_drvinit (void *unused)
{
#ifdef DEVFS
    int mynor;
    int unit;
#endif

    if (!maru_devsw_installed)
	{
	    if (at_shutdown (&marushutdown, NULL, SHUTDOWN_POST_SYNC))
		{
		    printf ("maru: could not install shutdown hook\n");
		    return;
		}
	    printf ("pre add: maru bdevsw.d_maj = %d\n", maru_bdevsw.d_maj);
	    bdevsw_add_generic (BDEV_MAJOR, CDEV_MAJOR, &maru_bdevsw);
	    printf ("post add: maru bdevsw.d_maj = %d\n", maru_bdevsw.d_maj);
	    printf ("post add: maru cdevsw.d_maj = %d\n", maru_cdevsw.d_maj);
#ifdef DEVFS
	    for (unit = 0; unit < NMARU; unit++)
		{
		    mynor = dkmakeminor (unit, WHOLE_DISK_SLICE, RAW_PART);
		    maru_devfs[unit] = devfs_add_devswf (&maru_bdevsw, mynor, DV_BLK,
							 UID_ROOT, GID_OPERATOR, 0640,
							 "maru%d", unit);
		    maru_rdevfs[unit] = devfs_add_devswf (&maru_cdevsw, mynor, DV_CHR,
							  UID_ROOT, GID_OPERATOR, 0640,
							  "rmaru%d", unit);
		}
#endif
	    maru_devsw_installed = 1;
	}
}

SYSINIT (marudev, SI_SUB_DRIVERS, SI_ORDER_MIDDLE + CDEV_MAJOR, maru_drvinit, NULL)

#ifdef ACTUALLY_LKM_NOT_KERNEL
#include <sys/exec.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/lkm.h>

MOD_MISC (maru);

static int maru_action (struct lkm_table *lkmtp, int cmd)
{
    int error = 0;
    switch (cmd)
	{
	case LKM_E_LOAD:
	    maru_drvinit (NULL);
	    break;
	case LKM_E_UNLOAD:
	    marushutdown (0, NULL);
	    /* not a real shutdown, so remove the hook */
	    rm_at_shutdown (&marushutdown, NULL);
	    break;
	case LKM_E_STAT:
	    break;
	default:
	    error = EIO;
	}
    return error;
}

int
maru_mod (struct lkm_table *lkmtp, int cmd, int ver)
{
#ifdef MOD_DISPATCH
    MOD_DISPATCH (maru, lkmtp, cmd, ver, maru_action, maru_action, maru_action);
#else
/* #define _module maru_module XXX */
    DISPATCH (lkmtp, cmd, ver, maru_action, maru_action, maru_action);
#endif
}
#endif /* ACTUALLY_LKM_NOT_KERNEL */
