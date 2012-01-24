/* Kernel User Environment driver for Linux
 *
 * author: Ralf-P. Weinmann <weinmann@rbg.informatik.tu-darmstadt.de>
 *         based on code supplied by Julian Assange <proff@iq.org>
 * 
 */

/* always include linux_compat.h first ! */
#include "linux_compat.h"

#include <linux/module.h>
#include <linux/malloc.h>
#include <linux/mm.h>
#include <linux/malloc.h>
#include <linux/fs.h>
#ifndef LINUX20
#include <linux/poll.h>

#include <asm/uaccess.h>
#endif
#include <asm/segment.h>
#ifndef LINUX20
#include <asm/spinlock.h>
#endif
#include <asm/string.h>
#include "kue_linux.h"
#include "kue-api.h"

#ifndef KUE_MAJOR
#define KUE_MAJOR		60
#endif

static int num_kue = NR_KUE;
int kue_msg_max = 1 << 16;	/* if we wanna sysctl this, we need a kernel
				   patch. hence leave it for now. */

struct kue_softc *kue_softc;

#ifdef DEBUG
#  define DB printk
#else
#  define DB 0 && printk
#endif

#define ERR        printk

/*
 * Delete last entry of chain and free associated memory
 */
static void
kue_free_kc (struct kue_softc *sc, struct kue_rchain *kc)
{
    DB("kue_free_kc(%p, %p)\n", sc, kc);

    TAILQ_REMOVE (&sc->sc_rhead, kc, kc_link);
    if (kc->kc_data)
	{
	    if (KAPI (sc) && sc->sc_kapi.ka_free_hook)
		sc->sc_kapi.ka_free_hook (kc->kc_data, kc->kc_len);
	    else
		kfree (kc->kc_data);
	}
    kfree (kc);
}

/*
 * Shutdown KUE activities on a device. this isn't safe yet.
 */
static int
kue_shutdown_sc (struct kue_softc *sc)
{
    struct kue_rchain *kc;
  
    DB ("kue_shutdown_sc(%p)\n", sc);
    /* wake up any waiting read() calls to tell them we're gone for now. */
    up (&sc->read_sem);
    while ((kc = TAILQ_FIRST (&sc->sc_rhead)))
	kue_free_kc (sc, kc);
    return 0;
}

inline static int
kue_readable (struct kue_softc *sc)
{
    return sc->sc_queue_min && (sc->sc_queue_size >= sc->sc_queue_min);
}

/*
 * Wrapper to kue_shutdown_sc()
 */

static int
kue_kapi_shutdown (struct kue_kapi *kapi)
{
    return kue_shutdown_sc (kapi->ka_sc);
}

/*
 * push data onto the read queue.
 * returns 0 or errno. caller should
 * not free injected data.
 */
EXPORT int kue_push (struct kue_kapi *kapi, void *p, int len)
{
    struct kue_rchain *kc;
    struct kue_softc *sc = kapi->ka_sc;

    DB ("kue_push(%p, %p, %d): kapi->ka_sc = %p\n", kapi, p, len, kapi->ka_sc);
    if (num_kue < 1 || !kapi || !(sc->sc_flags & KUF_INITED))
	return (-ENXIO);
    DB ("kue: sc->sc_flags = %d\n", sc->sc_flags);
    if (sc->sc_queue_size + len + sizeof(*kc) >= sc->sc_queue_max)
	return (-ENOBUFS);
    kc = kmalloc (sizeof *kc, GFP_KERNEL);
    if (!kc)
	return (-ENOMEM);
    kc->kc_data = p;
    kc->kc_len = len;
    sc->sc_queue_size += len + sizeof(*kc);
    TAILQ_INSERT_TAIL (&sc->sc_rhead, kc, kc_link);
    up (&sc->read_sem);		/* wake up any blocked task trying to read */
  
    /*
     * if minimum queue length for poll() is to a sensible value (!= 0)
     * and passed threshold, wake up any tasks blocking.
     */
    if (kue_readable(sc))
	wake_up(&sc->poll_wait);    
    return 0;
}

/*
 * Open instance of kue device. Only one instance per device allowed
 * if source is compiled with flag KUE_EXCLUSEVE_OPEN
 */
int 
kue_open (struct inode *i, struct file *f)
{
    ENTERSC (i->i_rdev);
    DB ("kue_open(%p, %p)\n", i, f);
#ifdef KUE_EXCLUSIVE_OPEN
    if (sc->sc_flags & KUF_INITED)
	EXITSC (-EBUSY);
#else
    if (!sc->sc_clients)
#endif
	{
	    TAILQ_INIT (&sc->sc_rhead);
	    sc->sc_queue_max = KUE_DEF_QUEUE_MAX;
	    sc->sc_queue_min = KUE_DEF_QUEUE_MIN;
	    sc->sc_flags |= KUF_INITED;
#ifdef EXCESSIVE_BAGGAGE  
	    sc->sc_kapi.ka_push = kue_push;
#endif /* EXCESSIVE_BAGGAGE */
	    sc->sc_kapi.ka_sc = sc;	/* backpointer */
	}
#ifndef KUE_EXCLUSIVE_OPEN
    sc->sc_clients++;
#endif
    MOD_INC_USE_COUNT;
    EXITSC (0);
}

/*
 * Close kue device (obviously this implies shutting down any kue activity
 * on that particular device)
 */
EXPORT int kue_release (struct inode *i, struct file *f)
{
    ENTERSC (i->i_rdev);
    DB ("kue_release(%p, %p)\n", i, f);
#ifndef KUE_EXCLUSIVE_OPEN
    if (sc->sc_clients > 0)
	    sc->sc_clients--;
    else
#endif
	{
	    if (!sc->sc_kapi.ka_shutdown)
		{
		    DB ("calling shutdown hooks\n");
		    (sc->sc_kapi).ka_shutdown(&sc->sc_kapi);
		}

	    kue_shutdown_sc(sc);
	    sc->sc_flags &= ~KUF_INITED;
	}

    MOD_DEC_USE_COUNT;
    EXITSC (0);
}

/*
 * Read data from kue device (this data has to be pushed onto the device queue
 * using kue_push() from another kernel module)
 */
#ifndef LINUX20
ssize_t 
kue_read (struct file *f, char *buf, size_t n, loff_t * ppos)
#else
int 
kue_read (struct inode *i, struct file *f, char *buf, int n)
#endif
{
    struct kue_rchain *kc;
    int len = 0;
#ifndef LINUX20
    ENTERSC (FINODE(f)->i_rdev);
#else
    ENTERSC (i->i_rdev);
#endif

    if ((f->f_flags & O_NONBLOCK) && !kue_readable(sc))
	EXITSC (-EWOULDBLOCK);

#ifndef LINUX20  
    DB ("kue_read(%p, %p, %u, %p)\n", f, buf, n, ppos);
#else
    DB ("kue_read(%p, %p, %p, %d)\n", i, f, buf, n);
#endif

    if (!(sc->sc_flags & KUF_INITED))
	EXITSC (-ENXIO);

    /* in order to be able to transfer a message we need at least be able to copy
     * the header into userspace
     */
    if (n < KUE_HLEN)
	EXITSC (-EINVAL);

    /* very kludgy. but till we get the semantics right this will work. */
    sc->read_sem = MUTEX_LOCKED;

    while (1)
	{
	    if ((kc = TAILQ_FIRST (&sc->sc_rhead)))
		break;
	    else
		{
		    int err;

		    err = down_interruptible (&sc->read_sem);

		    /* double-check. does the device still exist?
		     * maybe someone pulled it from under us.
		     */
		    if (!(sc->sc_flags & KUF_INITED))
			{
			    ERR ("kue: device %d disappeared during read.\n",
				 MINOR (FINODE(f)->i_rdev));
			    EXITSC (-ENXIO);
			}
		    if (err)
			EXITSC (err);
		}
	}

    while (kc)
	{
	    int err;
	    struct kue_message msg;

	    /* check whether we were told to prepend headers to kue
	     * messages. headers are turned on by default
	     */
	    if (!sc->sc_no_msg_hdr)
		{
		    if ((len + KUE_HLEN + kc->kc_len) >= n)
			EXITSC (len);
		    msg.km_len = kc->kc_len;
		    err = copy_to_user (buf + len, &msg, sizeof msg);
		    if (err)
			EXITSC (-EFAULT);
		    len += KUE_HLEN;
		} 
	    else if ((len + kc->kc_len) >= n)
		EXITSC (len);

	    if (KAPI (sc) && sc->sc_kapi.ka_read2_hook != NULL)
		{
		    err = sc->sc_kapi.ka_read2_hook (kc->kc_data, kc->kc_len, buf + len);
		    kc->kc_data = NULL;	/* read2 must free */
		    kue_free_kc (sc, kc);
		    if (err)
			EXITSC (err);
		}
	    else
		{
		    /* this will throw away the remaining data in the current kc buffer.
		     * message truncation is not a bug - it's a feature :)
		     */
		    err = copy_to_user (buf + len, kc->kc_data, kc->kc_len);
		    if (err)
			EXITSC (-EFAULT);
		    kue_free_kc (sc, kc);
		}
	    len += kc->kc_len;
	    sc->sc_queue_size -= sizeof (*kc) + kc->kc_len;
	    kc = TAILQ_FIRST (&sc->sc_rhead);
	}
    EXITSC (len);
}

/*
 * Write data to kue device. This data will be passed to the kernel module
 * associated with the kue device via the KAPI write hook.
 */
#ifndef LINUX20
ssize_t 
kue_write (struct file *f, const char *buf, size_t n, loff_t * ppos)
#else
int 
kue_write (struct inode *i, struct file *f, const char *buf, int n)
#endif
{
#ifndef LINUX20
    ENTERSC (FINODE(f)->i_rdev);
#else
    ENTERSC (i->i_rdev);
#endif

#ifndef LINUX20  
    DB ("kue_write(%p, %p, %u, %p)\n", f, buf, n, ppos);
#else
    DB ("kue_read(%p, %p, %p, %d)\n", i, f, buf, n);
#endif

    if (!(sc->sc_flags & KUF_INITED))
	EXITSC (-ENXIO);

    /* check whether we got a client to receive the data */
    if (!KAPI (sc) || !sc->sc_kapi.ka_write_hook)
	EXITSC (-ENODEV);


    /* first of all we check whether message headers are turned off.
     * if that's the case message handling is downright trivial.
     */
    if (sc->sc_no_msg_hdr)
	{
	    EXITSC(sc->sc_kapi.ka_write_hook (&sc->sc_kapi, n, buf));
	}
    else
	{
	    ssize_t written = 0;
	    
	    /* somebody might be passing us bogus messages. check length. */
	    if (n < KUE_HLEN)
		EXITSC (-EINVAL);
      
	    while (n > KUE_HLEN)
		{
		    int err;
		    struct kue_message msg;
	  
		    if (copy_from_user (&msg, buf, sizeof msg))
			EXITSC (-EFAULT);
		    /* check length of message */
		    if (msg.km_len < 0 || msg.km_len > kue_msg_max)
			EXITSC (-EINVAL);
		    buf += KUE_HLEN;
		    n -= KUE_HLEN;
		    written += KUE_HLEN;
		    if (msg.km_len == 0)
			continue;
		    /* write data to kernel client */
		    err = sc->sc_kapi.ka_write_hook (&sc->sc_kapi, msg.km_len, buf);
		    /* if write returned an error, abort operation and pass error back
		     * to userspace writer.
		     */
		    if (err < 0)
			EXITSC (err);
		    buf += msg.km_len;
		    n -= msg.km_len;
		    written += msg.km_len;
		}
	    EXITSC (written);
	}
}

EXPORT int kue_ioctl(struct inode *i, struct file *f, unsigned int cmd, unsigned long arg)
{
    int err = 0;
    int value;
    ENTERSC (i->i_rdev);

    switch(cmd) {
	/* turn message headers on/off */
    case KUEIOCTOGGLEHDR:
#ifndef LINUX20
	if (get_user(value, (int *) arg))
	    {
#else
	if (get_user(&value))
	    {
#endif
		err = -EFAULT;
		break;
	    }
	sc->sc_no_msg_hdr = !value;
	break;
	/* find out whether headers are on or off */
    case KUEIOCHDRSTATUS:
	value = !sc->sc_no_msg_hdr;
#ifndef LINUX20
	if (put_user(value, (int *) arg))
	    {
		err = -EFAULT;
		break;
	    }
#else
	if (verify_area(VERIFY_WRITE, (void *) arg, sizeof(int)))
	    {
		err = -EFAULT;
		break;
	    }
	put_user(value, (int *) arg);
	break;
#endif
    default:
	if (!(sc->sc_flags & KUF_INITED))
	    EXITSC (-ENXIO);

	/* check whether we got a client to receive the data */
	if (!KAPI (sc) || !sc->sc_kapi.ka_ioctl_hook)
	    err = -ENODEV;
	else
	    {
		DB("invoking kue ioctl proxy");
		err = sc->sc_kapi.ka_ioctl_hook(&sc->sc_kapi, i, f, cmd, arg);
	    }
    }
    EXITSC(err);
}

/*
 * a poll() / select() on a kue device can be explicitly woken up using
 * this function. otherwise poll() waits till the threshold or timeout (not yet)
 * is reached.
 */
void
kue_wakeup(struct kue_softc *sc)
{
    wake_up(&sc->poll_wait);
}

#ifndef LINUX20
EXPORT unsigned int kue_poll (struct file *f, struct poll_table_struct *pt)
{
    unsigned int mask = 0;
    ENTERSC (MINOR (FINODE(f)->i_rdev));

    DB ("kue_poll(%p, %p)\n", f, pt);
    if (!(sc->sc_flags & KUF_INITED))
	EXITSC (-ENXIO);

    /* gotta release the lock on the device during poll_wait, otherwise the
     * very idea of polling doesn't work. */
    up(&sc->lock_sem);
    poll_wait(f, &sc->poll_wait, pt);
    /* lock device again. */
    down_interruptible(&sc->lock_sem);
    /* careful. somebody might've pulled device from under us while we waited */
    if (!(sc->sc_flags & KUF_INITED))
	EXITSC (-ENXIO);
    /* check whether queue size is above threshold (for reading) */
    if (sc->sc_queue_size >= sc->sc_queue_min)
	{
	    mask |= POLLIN | POLLRDNORM;
	}
    /* check whether queue is full (for writing). */
    if (sc->sc_queue_size >= sc->sc_queue_max)
	{
	    mask |= POLLOUT | POLLWRNORM;
	}
    EXITSC (mask);
}

#else
/* select() is currently not supported under linux 2.0.x */
int 
kue_select (struct inode *i, struct file *f, int sel_type, select_table *wait)
{
  ERR("kue: select() functionality not supported by kue under linux 2.0.x\n");
}
#endif

static struct file_operations kue_fops =
{
    NULL,			/* llseek */
    kue_read,			/* read */
    kue_write,			/* write */
    NULL,		       	/* readdir */
#ifndef LINUX20
    kue_poll,			/* poll */
#else
    kue_select,			/* select */
#endif
    kue_ioctl,	                /* ioctl */
    NULL,		       	/* mmap */
    kue_open,			/* open */
#ifndef LINUX20
    NULL,		       	/* flush */
#endif
    kue_release,	       	/* release */
    NULL,		       	/* fsync */
#ifndef LINUX20
    NULL,		       	/* fasync */
    NULL,		       	/* check_media_change */
    NULL,		       	/* revalidate */
    NULL		       	/* lock */
#endif
};

/* replacement for the NetBSD KUEIOCGKAPI ioctl kludge */
EXPORT struct kue_kapi *kue_get_kapi (int minor, int reuse)
{
    struct kue_softc *sc;

    if (minor >= num_kue)
	return NULL;
    sc = &kue_softc[minor];

    if (down_interruptible (&sc->lock_sem) < 0)
	return NULL;
    if (KAPI(sc)) {
	up (&sc->lock_sem);
	return reuse ? &sc->sc_kapi : NULL;
    }

    sc->sc_flags |= KUF_KAPI;
    /* backpointer to sc */
    sc->sc_kapi.ka_sc = sc;
#ifdef NO_HEADERS_BY_DEFAULT
    /* turn message headers off by default */
    sc->sc_no_msg_hdr = 1;
#else
    /* turn message headers on by default */
    sc->sc_no_msg_hdr = 0;
#endif
  
    up (&sc->lock_sem);
    return &sc->sc_kapi;
}

EXPORT void kue_release_kapi(struct kue_kapi *kapi) 
{
    struct kue_softc *sc;

    if (!kapi || !kapi->ka_sc)
	return;

    sc = kapi->ka_sc;

    if (KAPI(sc)) {
	sc->sc_flags &= ~(KUF_KAPI);
	if (!sc->sc_kapi.ka_shutdown)
	    kue_shutdown_sc(sc);
	else
	    kapi->ka_shutdown(kapi);
    }
}

#ifdef MODULE
#define kue_drvinit init_module
#endif

int
kue_drvinit (void)
{
    struct kue_softc *mem;
    u_long size;
    int i;

    size = NR_KUE * sizeof (struct kue_softc);
    mem = kmalloc (size, GFP_KERNEL);
    if (mem == NULL)
	{
	    ERR ("kue: unable to allocate %ld bytes of memory for kue devices", size);
	    return -EIO;
	}
    memset (mem, 0, size);
    kue_softc = mem;
    for (i = 0; i < NR_KUE; i++)
        {
            kue_softc[i].lock_sem = MUTEX;
            kue_softc[i].read_sem = MUTEX_LOCKED;
        }

    if (register_chrdev (KUE_MAJOR, "kue", &kue_fops))
	{
	    ERR ("kue: unable to get major %d\n", KUE_MAJOR);
	    kfree (mem);
	    return -EIO;
	}

    printk ("kue: init successful on major %d\n", KUE_MAJOR);
    return 0;
}

#ifdef MODULE
void
cleanup_module (void)
{
    if (unregister_chrdev (KUE_MAJOR, "kue") != 0)
	printk ("kue: cleanup_module failed\n");
    else
	printk ("kue: driver removed\n");
    if (kue_softc)
	kfree (kue_softc);
}
#endif
