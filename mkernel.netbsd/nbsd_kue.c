/* $Id: nbsd_kue.c,v 1.2 1999/09/09 07:43:35 proff Exp $
 * $Copyright:$
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/conf.h>

#include "maru.h"
#include "kue-api.h"
#include "kue.h"

#include "nbsd_kue.h"

cdev_decl(kue);

#define KAPI(sc) ((sc)->sc_flags&KUF_KAPI)

#define DB printf

#define II printf("%s; %d\n", __FILE__, __LINE__);

#define KUE_DEF_QUEUE_MAX (128*1024)

typedef enum 
{
    KUF_INITED = 1<<0,
    KUF_WANTED = 1<<1,
    KUF_LOCKED = 1<<2,
    KUF_KAPI   = 1<<3	/* kapi hooks requested */
} kue_flags;

struct kue_rchain
{
    TAILQ_ENTRY(kue_rchain) kc_link;
    int kc_len;
    char *kc_data;
};

struct kue_softc
{
    kue_flags sc_flags; /* flags */
    int sc_min_read;	/* *not* including struct kue_message */
    int sc_min_write;	/* *not* including struct kue_message */
    int sc_queue_size;	/* memory used by read() queue */
    int sc_queue_max;	/* max queue size */
    TAILQ_HEAD(kue_rhead, kue_rchain) sc_rhead; /* pending read queue */
    struct kue_kapi sc_kapi; /* hooks etc */
} *kue_softc;

static int num_kue = 0;

int kue_msg_max = 1<<16; /* XXX sysctl this */

#define ENTERSC(dev)\
    struct kue_softc *sc;\
    do\
    {\
    int eerr;\
    if (minor(dev) >= num_kue)\
	return (ENXIO);\
    sc = &kue_softc[minor(dev)];\
    eerr = kue_lock(sc);\
    if (eerr!=0)\
	return (eerr);\
    } while(0);

#define EXITSC(err)\
    do\
    {\
        kue_unlock(sc);\
        return(err);\
    } while(0);

/*
 * Wait interruptibly for an exclusive lock.
 *
 * XXX
 * Several drivers do this; it should be abstracted and made MP-safe.
 */
static int
kue_lock(struct kue_softc *sc)
{
    int err;
    DB("kue_lock(%p)\n", sc);
#if 0
    while ((sc->sc_flags & KUF_LOCKED) != 0)
	{
	    sc->sc_flags |= KUF_WANTED;
	    if ((err = tsleep(sc, PUSER | PCATCH, "kuelck", 0)) != 0)
		return (err);
	}
    if (num_kue<1)
	return (ENXIO);
    sc->sc_flags |= KUF_LOCKED;
#endif
    return (0);
}


/*
 * Unlock and wake up any waiters.
 */
static void
kue_unlock(struct kue_softc *sc)
{
    DB("kue_unlock(%p)\n", sc);
#if 0
    sc->sc_flags &= ~KUF_LOCKED;
    if ((sc->sc_flags & KUF_WANTED) != 0)
	{
	    sc->sc_flags &= ~KUF_WANTED;
	    wakeup(sc);
	}
#endif
}

EXPORT void kueattach(int num)
{
    
    struct kue_softc *mem;
    u_long size;
    DB("kueattach(%d)\n", num);
    if (num < 1)
	return;
    size = num * sizeof(struct kue_softc);
    mem = malloc(size, M_DEVBUF, M_NOWAIT);
    if (mem == NULL)
	{
	    printf("WARNING: couldn't allocate %d bytes for %d kue devices\n", (int)size, num);
	    return;
	}
    bzero(mem, size);
    kue_softc = mem;
    num_kue = num;
}

static void
kue_free_kc(struct kue_softc *sc, struct kue_rchain *kc)
{
    DB("kue_free_kc(%p, %p)\n", sc, kc);
    TAILQ_REMOVE(&sc->sc_rhead, kc, kc_link);
    if (kc->kc_data)
    {
	if (KAPI(sc) && sc->sc_kapi.ka_free_hook)
	    sc->sc_kapi.ka_free_hook(kc->kc_data, kc->kc_len);
	else
	    free(kc->kc_data, M_DEVBUF);
    }
    free(kc, M_DEVBUF);
}
    
static void
kue_shutdown_sc(struct kue_softc *sc)
{
    struct kue_rchain *kc;
    DB("kue_shutdown_sc(%p)\n", sc);
    sc->sc_flags &= ~KUF_INITED;
    while ((kc=TAILQ_FIRST(&sc->sc_rhead)))
	kue_free_kc(sc, kc);
    bzero(sc, sizeof sc);
}

EXPORT void kuedetach()
{
    int n = num_kue;
    int m;
    DB("kue_detach()\n");
    num_kue = 0;
    for (m=0; m<n; m++)
	{
	    struct kue_softc *sc = &kue_softc[m];
	    kue_shutdown_sc(sc);
	    kue_unlock(sc);
	    bzero(sc, sizeof *sc);
	    wakeup(&sc->sc_rhead);
	}
    free(kue_softc, M_DEVBUF);
    kue_softc = NULL;
}

/*
 * inject data into the read queue.
 * returns 0 or errno. caller should
 * not free injected data.
 */
static int kue_inject(struct kue_kapi *kapi, void *p, int len)
{
    struct kue_rchain *kc;
    struct kue_softc *sc = kapi->ka_sc;
    DB("kue_inject(%p, %p, %d): kapi->ka_sc = %p\n", kapi, p, len, kapi->ka_sc);
    if (num_kue<1 ||
        !kapi ||
	!(sc->sc_flags&KUF_INITED))
	return (ENXIO);
II
    if (sc->sc_queue_size >= sc->sc_queue_max)
	return (ENOBUFS);
II
    kc = malloc(sizeof *kc, M_DEVBUF, M_NOWAIT);
    if (!kc)
	return (ENOMEM);
II
    kc->kc_data = p;
    kc->kc_len = len;
II
    TAILQ_INSERT_TAIL(&sc->sc_rhead, kc, kc_link);
II
    wakeup(&sc->sc_rhead); /* XXX speed */
II
    return 0;
}

static void
kue_kapi_shutdown(struct kue_kapi *kapi)
{
    kue_shutdown_sc(kapi->ka_sc);
}

int
kueopen(dev_t dev, int flags, int mode, struct proc *p)
{
    ENTERSC(dev);
    DB("kueopen(%d, %d, %d, %p)\n", dev, flags, mode, p);
    if (sc->sc_flags & KUF_INITED)
	EXITSC(EBUSY);
    TAILQ_INIT(&sc->sc_rhead);
    sc->sc_queue_max = KUE_DEF_QUEUE_MAX;
    sc->sc_flags |= KUF_INITED;
    /* init api */
    sc->sc_kapi.ka_inject = kue_inject;
    sc->sc_kapi.ka_shutdown = kue_kapi_shutdown;
    sc->sc_kapi.ka_sc = sc;
    EXITSC(0);
}

int
kueclose(dev_t dev, int flags, int mode, struct proc *p)
{
    ENTERSC(dev);
    DB("kueclose(%d, %d, %d, %p)\n", dev, flags, mode, p);
    kue_shutdown_sc(sc);
    EXITSC(0);
    return 0;
}

int
kueread(dev_t dev, struct uio *uio, int flags)
{
    struct kue_rchain *kc;
    ENTERSC(dev);
    DB("kueread(%d, %p, %d)\n", dev, uio, flags);
    if (!(sc->sc_flags&KUF_INITED))
	EXITSC(ENXIO);
    for (;;)
	{
    II
	    kc = TAILQ_FIRST(&sc->sc_rhead);
	    if (kc)
		{
		    break;
		}
	    else
		{
		    int err;
    II
		    err = tsleep((caddr_t)&sc->sc_rhead, PUSER|PCATCH, "kuread", 0);
		    if (!(sc->sc_flags&KUF_INITED)) /* device disappeared from under us */
			EXITSC(ENXIO);
    II
		    if (err && err != EWOULDBLOCK)
			EXITSC(err);
		}
	}
    while (kc)
	{
    II
	    if (uio->uio_resid < sizeof (*kc) + kc->kc_len)
		{
		    EXITSC(0);
		}
	    else
		{
		    int err;
		    struct kue_message msg;
    II
		    msg.km_len = kc->kc_len;
		    if (msg.km_len == 0)
			printf("kuread() msg.km_len = 0!\n");
		    err = uiomove((caddr_t)&msg, sizeof msg, uio);
		    if (err)
			EXITSC(err);
		    if (KAPI(sc) && sc->sc_kapi.ka_read2_hook)
			{
    II
			    err = sc->sc_kapi.ka_read2_hook(kc->kc_data, kc->kc_len, uio);
                            kc->kc_data = NULL; /* read2 must free */
			    kue_free_kc(sc, kc);
			    if (err)
				EXITSC(err);
			}
		    else
			{
    II
			    err = uiomove((caddr_t)kc->kc_data, kc->kc_len, uio);
		    	    kue_free_kc(sc, kc);
			    if (err)
				EXITSC(err);
			}
		    sc->sc_queue_size -= sizeof(kc) + kc->kc_len;
		    kc = TAILQ_FIRST(&sc->sc_rhead);
		}
    II
	}
    II
    EXITSC(0);
}    

int
kuewrite(dev_t dev, struct uio *uio, int flags)
{
    ENTERSC(dev);
    DB("kuewrite(%d, %p, %d) uio->uio_resid = %d\n", dev, uio, flags, uio->uio_resid);
    if (!(sc->sc_flags&KUF_INITED))
	EXITSC(ENXIO);
II
    if (!KAPI(sc) || !sc->sc_kapi.ka_write_hook)
	EXITSC(ENODEV);
II
    while (uio->uio_resid > 0)
	{
	    int err;
	    struct kue_message msg = {0xbabecafe};
	    if (uio->uio_resid < sizeof (struct kue_message))
		EXITSC(EINVAL);
II
	    err = uiomove((caddr_t)&msg, sizeof msg, uio);
	    if (err)
		EXITSC(err);
II
	    DB("kue_write() msg->km_len = %d\n", msg.km_len);
	    if (msg.km_len < 0 ||
		msg.km_len > kue_msg_max)
		EXITSC(EINVAL);
II
	    if (msg.km_len == 0) /* `duh' */
		continue;
II
	    err = sc->sc_kapi.ka_write_hook(&sc->sc_kapi, msg.km_len, uio);
II
	    /* write_hook MUST free p (eventually), even on error */
	    if (err)
		EXITSC(err);
	}
II
    EXITSC(0);
}

int
kueioctl (dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
    ENTERSC(dev);
    DB("kueioctl(%d, %ld, %p, %d, %p)\n", dev, cmd, data, flag, p);
    if (!(sc->sc_flags&KUF_INITED))
	EXITSC(ENXIO);
    switch (cmd)
	{
	case KUEIOCGKAPI:
	    {
		struct kue_kapi *kapi = &sc->sc_kapi;
	        memcpy(data, &kapi, sizeof(caddr_t));
		sc->sc_flags|=KUF_KAPI;
            }
	    break;
	default:
	    return (ENOTTY);
	}
    EXITSC(0);
}

int
kuepoll(dev_t dev, int events, struct proc *p)
{
    ENTERSC(dev);
    DB("kuepoll(%d, %d, %p)", dev, events, p);
    EXITSC(0);
}
