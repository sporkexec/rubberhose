/* $Id: nbsd_maru.c,v 1.4 1999/09/09 07:43:35 proff Exp $
 * $Copyright:$
 */

#include <sys/param.h>

#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/disklabel.h>
#include <sys/disk.h>
#include <sys/dkio.h>

#include "maru.h"
#include "kue-api.h"

#include "mkern-api.h"

bdev_decl(maru);
cdev_decl(maru);

#define DB printf

#define maruunit(x) DISKUNIT(x)
#define MARULABELDEV(dev) \
	(MAKEDISKDEV(major((dev)), maruunit((dev)), RAW_PART))

typedef enum
{
    MUF_INITED 		= 1<<0,		/* unit has been initialised */
    MUF_WLABEL 		= 1<<1,		/* label area is writable */
    MUF_LABELING	= 1<<2,		/* unit is currently being labeled */
} maru_flags;

struct maru_softc;

struct maru_token
{
    m_u32 qt_id;
    struct buf *qt_bp;
    struct maru_softc *qt_sc;
};

/* a token queue to associate block device
 * read requests and the (async) answer from userland
 */

#define NUM_TOKENS (NMARU * 8)

static struct maru_token *maru_tokens = NULL;
static int maru_tokens_active = 0;

struct maru_softc
{
    maru_flags sc_flags;	/* flags */
    int sc_writing;		/* outstanding writes */
    int sc_reading;		/* outstanding reads */
    int sc_clients;		/* active opens() */
    struct kue_kapi *sc_kapi;	/* pointer to kue kernel api */
#if 0
    struct disk sc_dkdev;	/* disk info */
#endif
    dev_t sc_dev;		/* our device */
    m_u64 sc_size;		/* size in bytes */
    char sc_xname[8];		/* XXX external name */
} *maru_softc;

static int num_maru = 0;

#define ENTERSC(dev)\
    struct maru_softc *sc;\
    do\
    {\
    int eerr;\
    if (maruunit(dev) >= num_maru)\
	return (ENXIO);\
    sc = &maru_softc[maruunit(dev)];\
    eerr = maru_lock(sc);\
    if (eerr!=0)\
	return (eerr);\
    } while(0);

#define EXITSC(err)\
    do\
    {\
        maru_unlock(sc);\
        return(err);\
    } while(0);

/*
 * Wait interruptibly for an exclusive lock.
 *
 * XXX
 * Several drivers do this; it should be abstracted and made MP-safe.
 */
static int
maru_lock(struct maru_softc *sc)
{
    int err;
    DB("maru_lock(%p)\n", sc);
#if 0
    while ((sc->sc_flags & MUF_LOCKED) != 0)
	{
	    sc->sc_flags |= MUF_WANTED;
	    if ((err = tsleep(sc, PUSER | PCATCH, "marulck", 0)) != 0)
		return (err);
	}
    if (num_maru<1)
	return (ENXIO);
    sc->sc_flags |= MUF_LOCKED;
#endif
    return (0);
}

/*
 * Unlock and wake up any waiters.
 */
static void
maru_unlock(struct maru_softc *sc)
{
    DB("maru_unlock(%p)\n", sc);
#if 0
    sc->sc_flags &= ~MUF_LOCKED;
    if ((sc->sc_flags & MUF_WANTED) != 0)
	{
	    sc->sc_flags &= ~MUF_WANTED;
	    wakeup(sc);
	}
#endif
}

static void
maru_berror(struct buf *bp, int err)
{
    DB("maru_berror(%p, %d)\n", bp, err);
    bp->b_flags |= B_ERROR;
    bp->b_error = err;
    biodone(bp);
}

EXPORT void maruattach(int num)
{
    
    struct maru_softc *mem;
    u_long size;
    DB("maruattach(%d)\n", num);
    if (num < 1)
	return;
    size = num * sizeof(struct maru_softc);
    mem = malloc(size, M_DEVBUF, M_NOWAIT);
    if (mem == NULL)
	{
	    printf("WARNING: couldn't allocate %d bytes for %d maru devices\n", (int)size, num);
	    return;
	}
    bzero(mem, size);
    maru_softc = mem;
    num_maru = num;
}

static struct maru_token *
maru_find_token(m_u32 id)
{
    struct maru_token *tok;
    m_u32 tid = id % NUM_TOKENS;
    DB("maru_find_token(%d): %d\n", id, tid);
    if (!maru_tokens)
	return NULL;
    tok = &maru_tokens[tid];
    if (tok->qt_id != id ||
        tok->qt_sc == NULL)
        {
	    printf("maru_find_token(%d) invalid token\n", id);
	    return NULL;
        }
    return tok;
}

static void
maru_release_token(struct maru_token *tok)
{
    int s;
    DB("maru_release_token(%p)\n", tok);
    s = splbio();
    bzero(tok, sizeof *tok);
    if (maru_tokens_active-- >= NUM_TOKENS)
	{
	    splx(s);
	    wakeup(maru_tokens);
	}
    else
	{
	    splx(s);
	}
}

static int
maru_acquire_token(struct maru_softc *sc, struct buf *bp)
{
    static m_u32 current_token;
    struct maru_token *tok;
    int n;
    DB("maru_acquire_token(%p, %p)\n", sc, bp);
    if (!maru_tokens)
	{
	    maru_tokens = malloc(NUM_TOKENS, M_DEVBUF, M_WAITOK);
	    bzero(maru_tokens, NUM_TOKENS);
	}
    for (;;)
	{
	    int s;
	    s = splbio();
	    if (maru_tokens_active >= NUM_TOKENS)
		{
		    splx(s);
		    tsleep(maru_tokens, PUSER, "mutok", 0);
		    continue;
		}
	    for (n=0; n<NUM_TOKENS; n++)
		if (maru_tokens[++current_token%NUM_TOKENS].qt_sc == NULL)
		    goto found;
	    splx(s);
	    printf("maru_acquire_token() it's locking jim, but not as we know it\n");
	found:
	    maru_tokens_active++;
	    tok = &maru_tokens[current_token%NUM_TOKENS];
	    tok->qt_sc = sc;
	    tok->qt_bp = bp;
	    tok->qt_id = current_token;
	    splx(s);
	    DB("maru_acquire_token() = %d/%d\n", current_token%NUM_TOKENS, current_token);
	    return current_token;
	}
    /* NOT REACHED */
}

static void
maru_shutdown_sc(struct maru_softc *sc)
{
    int n;
    int s;
    DB("maru_shutdown_sc(%p)\n", sc);
    s = splbio();
    if (sc->sc_flags&MUF_INITED)
    {
       disk_detach(&sc->sc_dkdev);
	    sc->sc_flags &= ~MUF_INITED;
 	   if (sc->sc_kapi)
    	    sc->sc_kapi->ka_shutdown(sc->sc_kapi);
    if (maru_tokens)
	{
	    for (n=0; n<NUM_TOKENS; n++)
		{
		    struct maru_token *tok = &maru_tokens[n];
		    if (tok->qt_sc == sc)
			{
			    if (tok->qt_bp)
				maru_berror(tok->qt_bp, ENXIO);
			    maru_release_token(tok);
			}
		}
	    if (maru_tokens_active == 0)
		{
		    free(maru_tokens, M_DEVBUF);
		    maru_tokens = NULL;
		}
	}
}
    splx(s);
}

EXPORT void marudetach()
{
    int n = num_maru;
    int m;
    DB("maru_detach()\n");
    num_maru = 0;
    for (m=0; m<n; m++)
	{
	    struct maru_softc *sc = &maru_softc[m];
	    maru_shutdown_sc(sc);
	    maru_unlock(sc);
	    bzero(sc, sizeof *sc);
	    wakeup(sc);
	}
    free(maru_softc, M_DEVBUF);
    maru_softc = NULL;
}


#if 0
/*
 * build standard adaptec ficticious geometry
 */
static void
maru_getdefaultlabel(struct maru_softc *sc, struct disklabel *lp)
{
    struct partition *pp;
    DB("maru_getdefaultlabel(%p, %p)\n", sc, lp);
    bzero(lp, sizeof *lp);
    lp->d_secsize = 512;
    lp->d_secperunit = sc->sc_size / lp->d_secsize;
    lp->d_nsectors = 32;
    lp->d_ntracks = 16;
    lp->d_ncylinders = sc->sc_size / (lp->d_nsectors * lp->d_secsize * lp->d_ntracks);
    lp->d_secpercyl = lp->d_ntracks * lp->d_nsectors;
    strncpy(lp->d_typename, "maru", sizeof(lp->d_typename));
    lp->d_type = DTYPE_VND; /* XXX compat */
    strncpy(lp->d_packname, "fictitious", sizeof(lp->d_packname));
    lp->d_rpm = 3600;
    lp->d_interleave = 1;
    lp->d_flags = 0;
 
    pp = &lp->d_partitions[RAW_PART];
    pp->p_offset = 0;
    pp->p_size = lp->d_secperunit;
    pp->p_fstype = FS_UNUSED;

    lp->d_npartitions = RAW_PART + 1;
    lp->d_magic = DISKMAGIC;
    lp->d_magic2 = DISKMAGIC;
    lp->d_checksum = dkcksum(lp);
}    

/*
 * Read the disklabel from a vnd.  If one is not present, create a fake one.
 */
static void
maru_getdisklabel(struct maru_softc *sc)
{
    struct disklabel *lp = sc->sc_dkdev.dk_label;
    struct cpu_disklabel *clp = sc->sc_dkdev.dk_cpulabel;
    int i;
    char *errstring;
    DB("maru_getdisklabel(%p)\n", sc);

    bzero(clp, sizeof(*clp));

    maru_getdefaultlabel(sc, lp);

    /*
     * Call the generic disklabel extraction routine.
     */

    errstring = "blah" ; /* readdisklabel(MARULABELDEV(sc->sc_dev), marustrategy, lp, clp); */
    if (errstring)
	{
	    /*
	     * Lack of disklabel is common, but we print the warning
	     * anyway, since it might contain other useful information.
	     */
	    printf("maru_getdisklable(%p) %s: %s\n", sc, sc->sc_xname, errstring);

	    /*
	     * For historical reasons, if there's no disklabel
	     * present, all partitions must be FS_BSDFFS and
	     * occupy the entire disk.
	     */

	    for (i = 0; i < MAXPARTITIONS; i++)
		{
		    /*
		     * Don't wipe out port specific hack (such as
		     * dos partition hack of i386 port).
		     */

		    if (lp->d_partitions[i].p_fstype != FS_UNUSED)
			continue;
		    
		    lp->d_partitions[i].p_size = lp->d_secperunit;
		    lp->d_partitions[i].p_offset = 0;
		    lp->d_partitions[i].p_fstype = FS_BSDFFS;
		}
	    
	    strncpy(lp->d_packname, "default label", sizeof(lp->d_packname));
	    lp->d_checksum = dkcksum(lp);
	}
}

#endif
int
maruopen(dev_t dev, int flags, int mode, struct proc *p)
{
    struct disklabel *lp;
    int part, pmask;
    ENTERSC(dev);
    DB("maruopen(%d, %d, %d, %p)\n", dev, flags, mode, p);
    sc->sc_dev = dev; /* XXX only actually need to do this on the first open */
#if 0
    if ((sc->sc_flags & MUF_INITED) &&
	(sc->sc_dkdev.dk_openmask == 0))
	maru_getdisklabel(sc);
    part = DISKPART(dev);
    pmask = (1 << part);
    lp = sc->sc_dkdev.dk_label;
    /* Check that the partion actually exists */
    if (part != RAW_PART &&
	(((sc->sc_flags & MUF_INITED) == 0) ||
	 ((part >= lp->d_npartitions) ||
	  (lp->d_partitions[part].p_fstype == FS_UNUSED))))
	EXITSC(ENXIO);
    /* Prevent our unit from being unconfigured while open. */
    switch (mode)
	{
	case S_IFCHR:
	    sc->sc_dkdev.dk_copenmask |= pmask;
	    break;
	    
	case S_IFBLK:
	    sc->sc_dkdev.dk_bopenmask |= pmask;
	    break;
	}
    sc->sc_dkdev.dk_openmask =sc->sc_dkdev.dk_copenmask | sc->sc_dkdev.dk_bopenmask;
#endif
    sc->sc_clients++;
    EXITSC(0);
}

int
maruclose(dev_t dev, int flags, int mode, struct proc *p)
{
    int part;
    ENTERSC(dev);
    DB("maruclose(%d, %d, %d, %p)\n", dev, flags, mode, p);
    --sc->sc_clients;
    part = DISKPART(dev);
    /* ...that much closer to allowing unconfiguration... */
    switch (mode)
	{
	case S_IFCHR:
	    sc->sc_dkdev.dk_copenmask &= ~(1 << part);
	    break;
	    
	case S_IFBLK:
	    sc->sc_dkdev.dk_bopenmask &= ~(1 << part);
	    break;
	}
    sc->sc_dkdev.dk_openmask =
	sc->sc_dkdev.dk_copenmask | sc->sc_dkdev.dk_bopenmask;
    EXITSC(0);
    return 0;
}

static void
maru_printbuf(struct buf *bp)
{
    DB("maru_printbuf(%p): b_flags=%lx b_data=%p b_bufsize=%ld b_bcount=%ld b_resid=%ld b_dev=%d b_lblkno=%d b_blkno=%d\n", bp, bp->b_flags, bp->b_data, bp->b_bufsize, bp->b_bcount, bp->b_resid, bp->b_dev, bp->b_lblkno, bp->b_blkno);
}

static int
maru_kue_free_callback(void *data, int len)
{
    struct maru_message *msg = data;
    struct buf *bp;
    struct maru_token *tok;
    DB("maru_free_callback(%p, %d)\n", data, len);
    tok = maru_find_token(msg->mm_id);
    free(msg, M_DEVBUF);
    if (!tok)
	return (EINVAL);
    bp = tok->qt_bp;
    maru_release_token(tok);
    if (bp)
	maru_berror(bp, ENXIO);
    return 0;
}

static int  /* read2 is read for userland -- that's a write for us */
maru_kue_read2_callback(void *data, int len, struct uio *uio)
{
    int err = EINVAL;
    struct maru_message *msg = data;
    struct buf *bp;
    struct maru_token *tok;
    DB("maru_kue_read2_callback(%p, %d, %p)\n", data, len, uio);
    tok = maru_find_token(msg->mm_id);
    if (!tok)
	{
	err:
	    free(msg, M_DEVBUF);
	    return (err);
	}
    bp = tok->qt_bp;
    err = uiomove((caddr_t)msg, sizeof *msg, uio);
    if (err)
	goto err;
    if (msg->mm_flags&MARU_WRITE)
	{
	    err = uiomove((caddr_t)bp->b_data, msg->mm_len, uio);
	    if (err)
		{
		    maru_berror(bp, err);
		    goto err;
		}
	    bp->b_resid -= msg->mm_len;
	    if (bp->b_resid<0)
		{
		    printf("bp->b_resid = %ld in maru_kue_read2_callback()\n", bp->b_resid);
		    bp->b_resid = 0;
		}
            maru_release_token(tok);
	    biodone(bp);
	    goto done;
	}
    if (msg->mm_flags&MARU_READ_REQ)
	{
	    DB("MAU_READ_REQ\n");
	    goto done;
	}
    DB("bad flags = %x\n", msg->mm_flags);
    /* XXX pad */
 done:
    free(msg, M_DEVBUF);
    return 0;
}

static int
maru_kue_write_callback(struct kue_kapi *kapi, int len, struct uio *uio)
{
    int err;
    struct maru_message msg;
    struct buf *bp;
    struct maru_token *tok;
    DB("maru_kue_write_callback(%p, %d, %p)\n", kapi, len, uio);
    err = uiomove(&msg, sizeof msg, uio);
    if (err)
	return (err);
    tok = maru_find_token(msg.mm_id);
    if (!tok)
	return (EINVAL);
    bp = tok->qt_bp;
    maru_release_token(tok);
    err = uiomove(bp->b_data, msg.mm_len, uio);
    if (err)
	{
	    maru_berror(bp, err);
	    return err;
	}
    bp->b_resid -= msg.mm_len;
    if (bp->b_resid<0)
	{
	    printf("bp->b_resid = %ld in maru_kue_write_callback()\n", bp->b_resid);
	    bp->b_resid = 0;
	}
    biodone(bp);
    return 0;
}

void
marustrategy(struct buf *bp)
{
    struct maru_softc *sc;
    struct disklabel *lp;
    struct partition *pp;
    int len;
    int err = ENXIO;
    m_u64 offset;
    DB("marustrategy(%p)\n", bp);
    maru_printbuf(bp);
	DB("ms:1\n");
    sc = &maru_softc[maruunit(bp->b_dev)];
    if (num_maru<1 ||
	maruunit(bp->b_dev) >= num_maru ||
	!(sc->sc_flags&MUF_INITED) ||
	!sc->sc_kapi)
	{
	err:
	DB("ms:2\n");
	    maru_berror(bp, err);
	DB("ms:3\n");
	    return;
	}
	DB("ms:4\n");
    len = bp->b_bcount;
    bp->b_resid = len;
    if (len<1)
	{
	DB("ms:5\n");
	    biodone(bp);
	DB("ms:6\n");
	    return;
	}
    DB("ms:6.1\n");
    offset = dbtob(bp->b_blkno);
    lp = sc->sc_dkdev.dk_label;
    /* the transfer must be a whole number of blocks */
    if (len % lp->d_secsize != 0)
	{
	    maru_berror(bp, EINVAL);
	    return;
	}
    
    /*
     * Do bounds checking and adjust transfer.  If there's an error,
     * the bounds check will flag that for us.
     */
    DB("ms:6.2\n");
    if (DISKPART(bp->b_dev) != RAW_PART &&
	bounds_check_with_label(bp, lp, sc->sc_flags&MUF_WLABEL) <= 0)
	{
	    biodone(bp);
	    return;
	}
    /*
     * Translate the partition-relative block number to an absolute.
     */
    DB("ms:6.3\n");
    if (DISKPART(bp->b_dev) != RAW_PART)
	{
	    pp = &sc->sc_dkdev.dk_label->d_partitions[DISKPART(bp->b_dev)];
	    offset += pp->p_offset * lp->d_secsize;
	}
    if (bp->b_flags & B_READ)
	{
	    struct maru_message *msg;
	DB("ms:7\n");
	    msg = malloc(sizeof *msg, M_DEVBUF, M_NOWAIT);
	    if (!msg)
		goto err;
	    msg->mm_flags = MARU_READ_REQ;
	DB("ms:8\n");
	    msg->mm_id = maru_acquire_token(sc, bp);
	    msg->mm_len = len;
	    msg->mm_offset = offset;
	DB("ms:9\n");
	    if ((err = sc->sc_kapi->ka_inject(sc->sc_kapi, msg, sizeof *msg)))
		{
	DB("ms:10\n");
		    free(msg, M_DEVBUF);
		    goto err;
		}
	DB("ms:11\n");
	    sc->sc_reading++;
	    return;
	}
    else /* B_WRITE */
	{
	    struct maru_message *msg;
	DB("ms:13\n");
	    msg = malloc(sizeof *msg, M_DEVBUF, M_NOWAIT);
	    if (!msg)
		goto err;
	    msg->mm_flags = MARU_WRITE;
	    msg->mm_id = maru_acquire_token(sc, bp);
	    msg->mm_len = len;
	    msg->mm_offset = offset;
	DB("ms:14\n");
	    if ((err = sc->sc_kapi->ka_inject(sc->sc_kapi, msg, sizeof(msg)+msg->mm_len)))
		{
	DB("ms:15\n");
		    free(msg, M_DEVBUF);
		    goto err;
		}
	DB("ms:16\n");
	    sc->sc_writing++;
	    return;
	}
	DB("ms:17\n");
}

int
maruread(dev_t dev, struct uio *uio, int flags)
{
    ENTERSC(dev);
    DB("maruread(%d, %p, %d)\n", dev, uio, flags);
    if (!(sc->sc_flags&MUF_INITED))
	EXITSC(ENXIO);
    EXITSC(physio(marustrategy, NULL, dev, B_READ, minphys, uio));
}    

int
maruwrite(dev_t dev, struct uio *uio, int flags)
{
    ENTERSC(dev);
    DB("maruwrite(%d, %p, %d)\n", dev, uio, flags);
    if (!(sc->sc_flags&MUF_INITED))
	EXITSC(ENXIO);
    EXITSC(physio(marustrategy, NULL, dev, B_WRITE, minphys, uio));
}

int
maruioctl (dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
    ENTERSC(dev);
    DB("maruioctl(%d, %ld, %p, %d, %p)\n", dev, cmd, data, flag, p);
    switch (cmd)
	{
	    case MARUIOCATTACH:
		{
		    struct maru_ioc_attach *ma = (struct maru_ioc_attach *)data;
		    int fd = ma->ma_kue_fd;
		    struct filedesc *fdp = p->p_fd;
		    struct file *fp;
		    int err;
		    struct stat st;
		    struct kue_kapi *kapi;
		    
		    if (ma->ma_size < 512 * 16 * 32)
			EXITSC(EINVAL);
		    if (fd>=fdp->fd_nfiles || (fp=fdp->fd_ofiles[fd]) == NULL)
			EXITSC(EBADF);
		    if (fp->f_type != DTYPE_VNODE)
			EXITSC(ENOENT); /* some fool handed us a socket */
		    /* ok, so, this is cheating a little :) */
		    err = vn_stat((struct vnode *)fp->f_data, &st, p);
		    if (err)
			EXITSC(err);

		    /* pull in a pointer to the kue kernel api. we need
		     * this hack in order to avoid nasty limitations in netbsd's
		     * kernel linker: symbols from one module
		     * are not linked against symbols from another, only
		     * the kernel image. we splinter a little wood */
		    err = fp->f_ops->fo_ioctl(fp, KUEIOCGKAPI, (caddr_t)&kapi, p);
		    DB("post ioctl");
		    if (err)
			EXITSC(err);
		    DB("post ioctl:2");
		    /* now install our hooks of evil */
		    sc->sc_kapi = kapi;
		    DB("post ioctl:3");
		    kapi->ka_read2_hook = maru_kue_read2_callback;
		    DB("post ioctl:4");
		    kapi->ka_free_hook = maru_kue_free_callback;
		    kapi->ka_write_hook = maru_kue_write_callback;

		    disk_attach(&sc->sc_dkdev);
		    
		    memcpy(&sc->sc_size, &ma->ma_size, sizeof sc->sc_size);
		    sc->sc_flags|=MUF_INITED;
		    maru_getdisklabel(sc);
		}
		break;
	case DIOCGDINFO:
	    maru_getdefaultlabel(sc, (struct disklabel*)data);
	    break;
	case DIOCGPART:
	    ((struct partinfo *)data)->disklab = sc->sc_dkdev.dk_label;
	    ((struct partinfo *)data)->part =
		&sc->sc_dkdev.dk_label->d_partitions[DISKPART(dev)];
	    break;
	case DIOCWDINFO:
	case DIOCSDINFO:
	    {
		int err;
		sc->sc_flags |= MUF_LABELING; /* marustrategy maybe called by writedisklabel() */
		err = setdisklabel(sc->sc_dkdev.dk_label,
				   (struct disklabel *)data, 0, sc->sc_dkdev.dk_cpulabel);
		if (!err)
		    {
			if (cmd == DIOCWDINFO)
			    err = writedisklabel(MARULABELDEV(dev),
						 marustrategy, sc->sc_dkdev.dk_label,
						 sc->sc_dkdev.dk_cpulabel);
		    }
		
		sc->sc_flags &= ~MUF_LABELING;

		if (err)
			EXITSC(err);
	    }
	    break;
	case DIOCWLABEL:
	    if (*(int *)data != 0)
		sc->sc_flags |= MUF_WLABEL;
	    else
		sc->sc_flags &= ~MUF_WLABEL;
	    break;
	case DIOCGDEFLABEL:
	    maru_getdefaultlabel(sc, (struct disklabel*)data);
	    break;
	default:
	    return (ENOTTY);
	}
    EXITSC(0);
}

int
marupoll(dev_t dev, int events, struct proc *p)
{
    ENTERSC(dev);
    DB("marupoll(%d, %d, %p)", dev, events, p);
    EXITSC(0);
}

int
marusize(dev_t dev)
{
    ENTERSC(dev);
    DB("marusize(%d)\n", dev);
    EXITSC(-1);
}

int
marudump(dev_t dev, daddr_t blkno, caddr_t va, size_t size)
{
    ENTERSC(dev);
    DB("marudump(%d, %d, %p, %d)\n", dev, blkno, va, size);
    /* XXX not implemented */
    EXITSC(ENXIO);
}
