/*
 * $Id: maru_linux.c,v 1.12 2000/08/17 13:02:56 ralphcvs Exp $
 *
 * marutukku kernel module for linux (supporting both 2.0.x and 2.2.x kernels now (well... maybe))
 *
 * Written by Ralf-Philipp Weinmann, 1999/07/12
 *
 * Copyright 1997-1999 Julian Assange & Ralf-P. Weinmann
 *
 * $Log: maru_linux.c,v $
 * Revision 1.12  2000/08/17 13:02:56  ralphcvs
 * bugfixes, bugfixes.
 * added {de,}keyaspect again cause {un,}bindaspect was broken
 * changed ioctl command names:
 * MARUIOC{AT,DE}TACH -> MARUIOC{,UN}BIND
 * MARUIOCISATTACHED -> MARUIOCISBOUND
 *
 * Revision 1.11  2000/08/17 08:14:14  ralphcvs
 * fix: multiple aspects couldn't be attached simultaneously.
 *
 * Revision 1.10  2000/08/04 13:45:57  ralphcvs
 * fixed several bugs in maru_kue_ioctl:
 * invalid ioctl on kue dev and ioctl proxy resulted in an infinite loop
 * maru_kue_ioctl emergency detach was broken
 *
 * Revision 1.9  2000/05/19 03:51:42  ralphcvs
 * maru_hunt_device() added.
 * two-way communication between hose and hose daemon introduced.
 *
 * Revision 1.8  2000/04/25 23:11:11  proff
 * fix exports, warnings
 *
 * Revision 1.7  2000/04/14 09:32:13  ralphcvs
 * changes in maru kernel module to disallow opening of aspect devices
 * unless the flag MUF_PERMISSIVE is set.
 *
 * Revision 1.6  2000/04/12 00:51:20  ralf
 * Aspect handling in process_maru_message() was broken. fixed.
 *
 * Revision 1.5  2000/04/10 07:22:08  ralf
 * The hose daemon seems to work with encryption enabled.
 *
 * Revision 1.4  2000/04/09 01:19:39  ralf
 * introduced MARU_ERROR for signalling errors to the kernel module.
 *
 * Revision 1.3  2000/04/04 17:20:01  ralf
 * hosed daemon rewritten from scratch. not yet functional
 *
 * Revision 1.2  1999/10/22 00:48:29  proff
 * changes from ralf
 *
 * Revision 1.1  1999/09/09 08:04:32  proff
 * changes from ralf
 *
 * Revision 1.1.1.1  1999/09/08 17:32:22  rpw
 * Initial import of Marutukku 0.7
 *
 * Revision 1.1.1.1  1999/08/10 15:17:20  rpw
 * import
 *
 * Revision 1.1  1999/07/25 21:48:16  ralphcvs
 * new marutukku kernel module(s) for linux 2.2 and above.
 * we now have a userspace daemon doing all the cryptographically related
 * work. user/kernelspace message passing is done using the KUE scheme
 * (via a character device). Consult the sources for details.
 *
 *
 */


/* always include linux_compat.h first ! */
#include "linux_compat.h"

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#ifndef LINUX20
#include <linux/init.h>
#endif
#include <linux/malloc.h>

#ifndef LINUX20
#include <asm/uaccess.h>
#endif

#include "maru_version.h"
#include "maru_config.h"
#include "maru_types.h"

#include "maru_bsd_ioctl.h"
#include "maru_linux.h"
#include "kue-api.h"
#include "mkern-api.h"
#include "kue_linux.h"
#include "queue.h"

#ifndef MARU_MAJOR
#define MARU_MAJOR	LOOP_MAJOR
#endif

#undef MARU_MAJOR
#define MARU_MAJOR	LOOP_MAJOR

#define DEVICE_NAME		"marutukku"
#define DEVICE_REQUEST	        maru_request
#define DEVICE_NR(device)	(MINOR(device))
#define DEVICE_ON(device)
#define DEVICE_OFF(device)
#define DEVICE_NO_RANDOM
#define TIMEOUT_VALUE		(6 * HZ)
#define MAJOR_NR		MARU_MAJOR

#define MARU_DEFAULT_BLOCKSIZE	1024

#include <linux/blk.h>

static struct maru_softc *maru_softc;

static int	maru_sizes[NMARU];
static int	maru_blksizes[NMARU];

static struct	maru_token *maru_tokens = NULL;
static m_u32	maru_tokens_active = 0, maru_outstanding_tokens = 0;
#if 0
static m_u32    maru_requests = 0, maru_outstanding_requests = 1;
#endif
#ifdef DECLARE_MUTEX_LOCKED
DECLARE_MUTEX_LOCKED(maru_token_lock);
#if 0
DECLARE_MUTEX(maru_request_lock);
#endif
#else
static struct	semaphore maru_token_lock = MUTEX_LOCKED;
#if 0
static struct   semaphore maru_request_lock = MUTEX;
#endif
#endif

static struct maru_token *
maru_find_token(m_u32 id)
{
    struct maru_token *tok;    
    m_u32 tid = id % NUM_TOKENS;

    DB(DEVICE_NAME ": maru_find_token(%d): %d\n", id, tid);

    /* token buffer not yet allocated/initialized */
    if (!maru_tokens)
	{
	    ERR(": token buffer not yet initialized.\n");
	    return NULL;
	}

    tok = &maru_tokens[tid];

    if (tok->qt_id != id || tok->qt_sc == NULL)
      {
	ERR(DEVICE_NAME ": maru_find_token(%d) invalid token\n", id);
	return NULL;
      }
    return tok;
}

static void
maru_release_token(struct maru_token *tok)
{
    DB(DEVICE_NAME ": maru_release_token(%p)\n", tok);
    
    if (!tok)
      return;

    memset(tok, 0, sizeof(struct maru_token));
    maru_tokens_active--;

    if (maru_outstanding_tokens > 0)
      {
	maru_outstanding_tokens--;
	DB(DEVICE_NAME ": maru_outstanding_tokens=%d\n",
	   maru_outstanding_tokens);
	up(&maru_token_lock);
      }
}

static int
maru_acquire_token(struct maru_softc *sc, struct request *req)
{
    static m_u32 current_token;
    struct maru_token *tok;
    int n;
  
    DB(DEVICE_NAME ": maru_acquire_token(%p, %p)\n", sc, req);

    if (!maru_tokens)
      {
	if ((maru_tokens = kmalloc(sizeof (struct maru_token) * NUM_TOKENS,
				 GFP_KERNEL)) == NULL)
	  return -ENOBUFS;

	memset(maru_tokens, 0, sizeof (struct maru_token) * NUM_TOKENS);
      }

    for (;;)
      {
	if (maru_tokens_active >= NUM_TOKENS)
	    {
		maru_outstanding_tokens++;
	        DB(DEVICE_NAME ": maru_outstanding_tokens=%d\n",
	               maru_outstanding_tokens);
		down(&maru_token_lock);
		DB(DEVICE_NAME ": woken up on token lock.\n");
	    }
	for (n = 0; n < NUM_TOKENS; n++)
	    if (maru_tokens[++current_token%NUM_TOKENS].qt_sc == NULL)
		goto found;
	ERR(DEVICE_NAME ": maru_acquire_token() it's locking jim, but not as we know it\n");
	return -ENOBUFS;
    found:
	maru_tokens_active++;
	tok = &maru_tokens[current_token%NUM_TOKENS];
	tok->qt_sc = sc;
	tok->qt_req = req;
	tok->qt_id = current_token;
	DB(DEVICE_NAME ": maru_acquire_token() = %d/%d\n", current_token%NUM_TOKENS,
	   current_token);
      
	return current_token;
    }
    /* NOT REACHED */
}

static inline void
maru_berror(struct request *req)
{
    DB(DEVICE_NAME ": maru_berror(%p)\n", req);
    spin_lock_irq(&io_request_lock);
    CURRENT = req;
    spin_unlock_irq(&io_request_lock);
    end_request(0);
}

static int
maru_free_callback(void *data, int len)
{
    struct maru_message *msg = data;
    struct maru_token *tok;
    
    DB("maru_free_callback(%p, %d)\n", data, len);
    
    tok = maru_find_token(msg->mm_id);
    kfree(msg);
    if (!tok)
	return -EINVAL;
    maru_release_token(tok);
    
    return 0;
}

static int maru_detach(struct maru_softc *sc, int force)
{
    struct maru_token *tok;
    int j;

    /* check whether there is an extent attached to the device */
    if (!(sc->sc_flags & MUF_INITED))
	{
	    ERR(DEVICE_NAME ": nothing to detach.\n");
	    return -EINVAL;
	}

    /* we cannot detach if there are still clients active on the
     * device unless force is activated.
     */
    if (!force && sc->sc_clients > 1)
	return -EBUSY;

    /* release all tokens for outstanding requests */
    if (maru_tokens)
	for(j = 0; j < NUM_TOKENS; j++)
	    {
		tok = &maru_tokens[j];
		if (tok->qt_req && tok->qt_sc == sc) {
		    maru_berror(tok->qt_req);
		    maru_release_token(tok);
		}
	    }

    if (--sc->sc_kapi->ka_refcount < 1) {
	/* release control of the kue API structure */
	kue_release_kapi(sc->sc_kapi);
    }

    sc->sc_flags &= ~MUF_INITED;
    invalidate_buffers(sc->sc_marudev);
    return 0;
}

/* we have to sanitize the internal state upon closure of the kue file descriptor */
static int
maru_shutdown(struct kue_kapi *ka)
{
    struct maru_kclnt *kclnt;
    int rval = 0;

    LIST_FOREACH(ka->ka_kclntdata, kclnt) {
	    if (rval < 0)
	    	maru_detach(kclnt->sc, 1);
	    else
		rval = maru_detach(kclnt->sc, 1);
    }
    LIST_DESTROY((struct maru_kclnt *) ka->ka_kclntdata);
    return rval;
}

/* entry point of ioctl proxy. useful for emergency detaches etc. */
static int
maru_kue_ioctl(struct kue_kapi *ka, struct inode *i, struct file *f,
	       unsigned int cmd, unsigned long arg)
{
  if (!i)
      {
	  NOTICE(DEVICE_NAME ": invalid inode (NULL pointer)\n");
          return -EINVAL;
      }

  switch(cmd) {
  case MARUIOCUNBIND:
      return maru_shutdown(ka);
  default:
      ERR(DEVICE_NAME "ioctl %d not implemented (device %s)", cmd, kdevname(i->i_rdev));
      return -1;
  }
}

/* data going to userland daemon */
static int
maru_read2_callback(void *data, size_t len, void *buf)
{
    struct maru_message *msg = data;
    struct request *req;
    struct maru_token *tok;
    int err;
    
    DB("maru_read2_callback(%p, %d, %p)\n", data, len, buf);
    tok = maru_find_token(msg->mm_id);
    
    /* no token found ? */
    if (!tok)
	goto done;

    req = tok->qt_req;

    err = copy_to_user(buf, msg, sizeof *msg);
    
    if (err)
	goto done;
    if (msg->mm_flags&MARU_WRITE)
	{
	    err = copy_to_user(buf + sizeof *msg, req->buffer, msg->mm_len);
	    if (err)
		maru_berror(req);
	    goto done;
	}
    if (msg->mm_flags&MARU_READ_REQ)
	{
	    DB("MARU_READ_REQ\n");
	    goto done;
	}
    maru_berror(req);
    DB("bad flags = %x\n", msg->mm_flags);
    /* XXX pad */
 done:
    kfree(msg);
    return 0;
}

/* for data coming back from userland (written to /dev/kue[0-9]) */
static int
maru_write_callback(struct kue_kapi *kapi, size_t len, const void *buf)
{
    int err;
    struct maru_message msg;
    struct request *req, *saved_req;
    struct maru_token *tok;
    
    DB("maru_write_callback(%p, %d, %p)\n", kapi, len, buf);
    err = copy_from_user(&msg, buf, sizeof msg);
    if (err)
	return (err);
    tok = maru_find_token(msg.mm_id);
    if (!tok)
	return -EINVAL;

    req = tok->qt_req;
    if (msg.mm_len != SECT2BYTES(req->current_nr_sectors))
	{
	    NOTICE(DEVICE_NAME ": invalid length of data (%u != %lu)", msg.mm_len,
		   SECT2BYTES(req->current_nr_sectors));
	    maru_berror(req);
	    return -EINVAL;
	}

    if (msg.mm_flags & MARU_ERROR)
      {
	  maru_berror(req);
	  return -EINVAL;
      }

    if (msg.mm_flags & MARU_READ)
      {
	err = copy_from_user(req->buffer, buf + sizeof msg, msg.mm_len);
	if (err)
	  {
	    maru_berror(req);
	    return err;
	  }
      }

    maru_release_token(tok);

    spin_lock_irq(&io_request_lock);
    saved_req = CURRENT;
    CURRENT = req;
    end_request(1);
    CURRENT = saved_req;
    spin_lock_irq(&io_request_lock);
    return 0;
}


static void
maru_request(void)
{
    int unit;
    struct maru_softc *sc;
    struct request *creq;
    struct maru_message *msg;

    DB(DEVICE_NAME ": maru_request() entered.\n");

    INIT_REQUEST;
    creq = CURRENT;
    while (creq)
	{
	    if ((unit = maruunit(creq->rq_dev)) >= NMARU)
		{
		    DB(DEVICE_NAME ": minor number out of range\n");
		    goto bail_out;
		}

	    sc = &maru_softc[unit];
	    if (!(sc->sc_flags & MUF_INITED))
		{
		    DB(DEVICE_NAME ": no marutukku extent attached to device\n");
		    goto bail_out;
		}
	    creq->errors = 0;
#ifndef LINUX20
	    spin_unlock_irq(&io_request_lock);
#endif
	    down(&sc->sc_lock);

	    switch(creq->cmd) {
	    case READ:
		msg = kmalloc(sizeof(struct maru_message), GFP_KERNEL);
		msg->mm_flags = MARU_READ_REQ;
		msg->mm_id = maru_acquire_token(sc, creq);
		msg->mm_len = SECT2BYTES(creq->current_nr_sectors);
		msg->mm_offset = SECT2BYTES(creq->sector);
		msg->mm_aspect = sc->sc_aspect;
	    
		DB(DEVICE_NAME ": MARU_READ_REQ: kue_push(%p, %p) len: %d, offset: %d\n",
		   sc->sc_kapi, msg, msg->mm_len, (int)msg->mm_offset);

		if (!(sc->sc_flags & MUF_INITED))
		    goto error_out;
		
		if (kue_push(sc->sc_kapi, msg, sizeof(struct maru_message)))
		  {
		    ERR(DEVICE_NAME ": kue_push() failed\n");
		    maru_berror(creq);
		    maru_free_callback((char *) msg, 0);
		    goto error_out;
		  }
		sc->sc_reading++;
		break;
	    case WRITE:
		if (sc->sc_flags & MUF_READONLY)
		    goto error_out;
		msg = kmalloc(sizeof *msg, GFP_KERNEL);
		msg->mm_flags = MARU_WRITE;
		msg->mm_id = maru_acquire_token(sc, creq);
		msg->mm_len = SECT2BYTES(creq->current_nr_sectors);
		msg->mm_offset = SECT2BYTES(creq->sector);
		msg->mm_aspect = sc->sc_aspect;
	    
		DB(DEVICE_NAME ": MARU_WRITE: kue_push(%p, %p) len: %d, offset: %d\n",
		   sc->sc_kapi, msg, msg->mm_len, (int)msg->mm_offset);
	    
		if (!(sc->sc_flags & MUF_INITED))
		    goto error_out;
		
		if (kue_push(sc->sc_kapi, msg, sizeof(struct maru_message) + msg->mm_len)) {
		    ERR(DEVICE_NAME ": out of memory while trying to push message onto kue stack\n");
		    maru_berror(creq);
		    maru_free_callback((char *) msg, 0);
		    goto error_out;
		}
		sc->sc_writing++;
		break;
	    default:
		ERR(DEVICE_NAME ": unknown device command (%d)\n",
		    creq->cmd);
		goto error_out;
	    }
	    up(&sc->sc_lock);
#ifndef LINUX20
	    spin_lock_irq(&io_request_lock);
#endif
	    CURRENT = creq = creq->next;
	    continue;
	
	error_out:
	    up(&sc->sc_lock);
#ifndef LINUX20
	    spin_lock_irq(&io_request_lock);
#endif
	bail_out:
	    creq->errors++;
	    end_request(0);
	    CURRENT = creq = creq->next;
	}
    DB(DEVICE_NAME ": exiting maru_request().\n");
}

static int
maru_ioctl(struct inode *i, struct file *f, unsigned int cmd,
	   unsigned long arg)
{
    ENTERSC(i);
  
    DB(DEVICE_NAME ": maru_ioctl(%p, %p, %x, %lx)\n", i, f, cmd, arg);

    switch(cmd) {
    case MARUIOCISBOUND:
	/* check whether this maru device is already bound */
	if (sc->sc_flags & MUF_INITED)
	    EXITSC(-EBUSY);
	break;
	
    case MARUIOCPERMISSIVE:
	/* ioctl command for turning permissive mode on/off */
	/* XXX explain impacts of permissive mode */
	if (arg)
	    sc->sc_flags |= MUF_PERMISSIVE;
	else
	    sc->sc_flags &= ~MUF_PERMISSIVE;
	break;
    case MARUIOCBIND:
	{
	    struct maru_ioc_attach ma;
	    struct kue_kapi *kapi;
	    struct maru_kclnt *kclnt;
	    int fd;
	    struct file *fp;

	    if(copy_from_user(&ma, (void *) arg, sizeof(struct maru_ioc_attach)))
		EXITSC(-EFAULT);

	    sc->sc_size = ma.ma_size;
	    sc->sc_aspect = ma.ma_aspect;

	    /* check whether maru device is already bound */
	    if (sc->sc_flags & MUF_INITED)
		EXITSC(-EBUSY);

	    fd = ma.ma_kue_fd;

	    /* check whether file descriptor is valid */
#ifndef LINUX20
	    if (fd >= current->files->max_fds || (fp=current->files->fd[fd]) == NULL)
#else
	    if (fd >= NR_OPEN || (fp=current->files->fd[fd]) == NULL)
#endif
		EXITSC(-EBADF);

	    /* kue devices are character devices. sanity check. */
	    if (!S_ISCHR(FINODE(fp)->i_mode)) {
		ERR(DEVICE_NAME ": kue file descriptor doesn't refer to a character device\n");
	    }

	    /* try to obtain pointer to kue API structure for installing hooks */
	    if (!(kapi = kue_get_kapi(maruunit(FINODE(fp)->i_rdev), 1))) {
		ERR(DEVICE_NAME ": cannot install kue hooks\n");
		EXITSC(-EINVAL);
	    }

	    /* install kue API callback and ioctl functions */
	    sc->sc_kapi = kapi;

	    if (kapi->ka_refcount++ < 1) {
		kapi->ka_read2_hook = maru_read2_callback;
		kapi->ka_free_hook  = maru_free_callback;
		kapi->ka_write_hook = maru_write_callback;
		kapi->ka_ioctl_hook = maru_kue_ioctl;
		kapi->ka_shutdown   = maru_shutdown;
	    }
		
	    kclnt = LIST_NEW(struct maru_kclnt);
	    kclnt->sc = sc;

	    if (LIST_EMPTY(kapi->ka_kclntdata)) {
		kapi->ka_kclntdata = kclnt;
		LIST_NEXT((struct maru_kclnt *) kapi->ka_kclntdata) = NULL;
	    } else
		LIST_INSERT_HEAD((struct maru_kclnt *) kapi->ka_kclntdata, kclnt);

	    sc->sc_flags |= MUF_INITED;

	    maru_sizes[maruunit(i->i_rdev)] = sc->sc_size;
	    /* invalidate buffers for this device. just a precaution */
	    invalidate_buffers(i->i_rdev);
	    break;
	}

    case MARUIOCUNBIND:
	/* XXX check whether passing options by value (instead of reference)
	 *     is a problem for ioctls
	 */
	EXITSC(maru_detach(sc, arg));
	/* NOTREACHED */

    case MARUIOCSETBLKSIZE:
	if(copy_from_user(&maru_blksizes[maruunit(i->i_rdev)], (void *) arg, sizeof(unsigned int)))
	    EXITSC(-EFAULT);
	invalidate_buffers(i->i_rdev);
	break;

    case BLKGETSIZE:
	put_user(sc->sc_size >> 9, (long *) arg);
    }
    EXITSC(0);
}

static int
maru_open(struct inode *i, struct file *f)
{
    ENTERSC(i);
    DB(DEVICE_NAME ": maruopen(%p, %p)\n", i, f);

    if (!(sc->sc_flags & MUF_PERMISSIVE) && sc->sc_euid != current->euid)
	EXITSC(-EINVAL);

    if (!sc->sc_clients) {
	/* store the current effective user id for future reference */
	sc->sc_euid   = current->euid;
	sc->sc_flags &= ~MUF_PERMISSIVE; 
    }
    
    sc->sc_clients++;
  
    MOD_INC_USE_COUNT;

    EXITSC(0);
}

static int
maru_close(struct inode *i, struct file *f)
{
    ENTERSC(i);
    DB(DEVICE_NAME ": maruclose(%p, %p)\n", i, f);

    if (sc->sc_clients > 0)
	sc->sc_clients--;
  
    MOD_DEC_USE_COUNT;
    EXITSC(0);
}

ssize_t maru_block_write(struct file * filp, const char * buf, size_t count, loff_t *ppos)
{
  if(filp)
    filp->f_flags |= O_SYNC;
  return block_write(filp, buf, count, ppos);
}

ssize_t maru_block_read(struct file * filp, char * buf, size_t count, loff_t *ppos)
{
  if(filp)
    filp->f_flags |= O_SYNC;
  return block_read(filp, buf, count, ppos);
}

static struct file_operations maru_file_ops = {
    NULL,			/* lseek - default */
    maru_block_read,		/* read - general block-dev read */
    maru_block_write,		/* write - general block-dev write */
    NULL,			/* readdir - bad */
    NULL,			/* poll */
    maru_ioctl,			/* ioctl */
    NULL,			/* mmap */
    maru_open,			/* open */
#ifndef LINUX20
    NULL,			/* flush */
#endif
    maru_close			/* release */
};

/*
 * And now the modules code and kernel interface.
 */
#ifdef MODULE
#define maru_init init_module
#endif

void cleanup_module(void);

#ifndef LINUX20
int __init maru_init(void) 
#else
int maru_init(void)
#endif
{
    int	i;
  
    if (register_blkdev(MAJOR_NR, DEVICE_NAME, &maru_file_ops)) {
	ERR(DEVICE_NAME ": cannot register device (major: %d)",
	    MAJOR_NR);
	return -EIO;
    }
#ifndef MODULE
    NOTICE(DEVICE_NAME ": registered device at major %d\n", MAJOR_NR);
#else
    NOTICE(DEVICE_NAME ": driver loaded (major %d)\n", MAJOR_NR);
#endif

    blk_dev[MAJOR_NR].request_fn = DEVICE_REQUEST;
    memset(&maru_sizes, 0, sizeof(maru_sizes));
    memset(&maru_blksizes, 0, sizeof(maru_blksizes));
    if ((maru_softc = kmalloc(sizeof(struct maru_softc) * NMARU, GFP_KERNEL)) == NULL) {
	ERR(DEVICE_NAME ": unable to allocate memory\n");
	cleanup_module();
	return -ENOBUFS;
    }

    memset(maru_softc, 0, sizeof(struct maru_softc) * NMARU);
    for(i = 0; i < NMARU; i++) {
#ifdef DECLARE_MUTEX_LOCKED
	init_MUTEX_LOCKED(&maru_softc[i].sc_lock);
	init_MUTEX_LOCKED(&maru_softc[i].sc_tlock);
#else
	/* XXX rpw 2000/08/01 is this correct ??? */
	maru_softc[i].sc_lock = MUTEX;
	maru_softc[i].sc_tlock = MUTEX;
#endif
	maru_softc[i].sc_num_tokens = NUM_TOKENS;
	maru_softc[i].sc_marudev = MKDEV(MARU_MAJOR, i);
	maru_blksizes[i] = MARU_DEFAULT_BLOCKSIZE;
    }
    blk_size[MAJOR_NR] = maru_sizes;
    blksize_size[MAJOR_NR] = maru_blksizes;
  
    return 0;
}

#ifdef MODULE
void cleanup_module(void) 
{
    NOTICE(DEVICE_NAME ": unloading driver\n");
    if (maru_softc)
	kfree(maru_softc);
    if (unregister_blkdev(MAJOR_NR, DEVICE_NAME) != 0)
	ERR(DEVICE_NAME ": cannot unregister driver\n");
}
#endif
