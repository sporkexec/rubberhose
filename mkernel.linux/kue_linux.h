#ifndef _KUE_LINUX_H
#define _KUE_LINUX_H

#ifndef LINUX_VERSION_CODE
#error "only linux kernel revisions 2.0 and above can use the KUE API"
#elsif LINUX_VERSION_CODE < KERNEL_VERSION(2,0,0)
#error "only linux kernel revisions 2.0 and above can use the KUE API"
#endif

#include <linux/sem.h>
#include "queue.h"

#if 0
#define KUE_MAJOR	99
#endif
#define NR_KUE          16

#define KAPI(sc) ((sc)->sc_flags&KUF_KAPI)
#define KUE_DEF_QUEUE_MAX (128*1024)
#define KUE_DEF_QUEUE_MIN 1


struct kue_kapi /* non opaque part of kue_softc */
{
  /* hook: called immediately after writing kc_data */
  int (*ka_read2_hook)(void *, size_t, void *);
  /* hook: called on error / exit */
  int (*ka_free_hook)(void *, int);
  /* hook: deliver data */
  int (*ka_write_hook)(struct kue_kapi *, size_t, const void *);
#ifdef EXCESSIVE_BAGGAGE /* we don't need this any more */
  /* push data onto read queue */
  int (*ka_push)(struct kue_kapi *, void *, int);
#endif /* EXCESSIVE_BAGGAGE */
  /* ioctl proxy */
  int (*ka_ioctl_hook)(struct kue_kapi *, struct inode *, struct file *,
		       unsigned int, unsigned long);
  /* shutdown */
  int (*ka_shutdown)(struct kue_kapi *);
  /* opaque backpointer to kue_softc */
  void *ka_sc;
  /* opaque pointer for kernel clients */
  void *ka_kclntdata;
  /* reference count */
  int ka_refcount;
};

typedef enum 
{
  KUF_INITED = 1<<0,
  KUF_KAPI   = 1<<1	/* kapi hooks requested */
} kue_flags;

struct kue_rchain
{
  TAILQ_ENTRY(kue_rchain) kc_link;
  int kc_len;
  char *kc_data;
};

struct kue_softc
{
  kue_flags sc_flags;          /* flags */
  struct semaphore lock_sem;   /* semaphore used for locking struct */
  struct semaphore read_sem;   /* semaphore for blocking reads */
  struct wait_queue *poll_wait;/* waitqueue for poll() */
  int sc_queue_size;	       /* memory used by read() queue */
  int sc_queue_min;	       /* min queue size */
  int sc_queue_max;	       /* max queue size */
  int sc_timeout;              /* timeout for poll/read */
  int sc_no_msg_hdr;           /* will headers be prepended to messages ? */
#ifndef KUE_EXCLUSIVE_OPEN
  int sc_clients;	       /* num of clients having this kue device open */
#endif
  TAILQ_HEAD(kue_rhead, kue_rchain) sc_rhead; /* pending read queue */
  struct kue_kapi sc_kapi;     /* hooks etc */
};

#ifndef ENTERSC
#define ENTERSC(dev)\
    struct kue_softc *sc;\
    {do\
    {\
    int eerr;\
    if (MINOR(dev) >= num_kue)\
        return (-ENXIO);\
    sc = &kue_softc[MINOR(dev)];\
    eerr = down_interruptible(&sc->lock_sem);\
    if (eerr!=0)\
        return (eerr);\
    } while(0);}
#endif

#ifndef EXITSC
#define EXITSC(err)\
    {do\
    {\
        up(&sc->lock_sem);\
        return(err);\
    } while(0);}
#endif

#define KUEIOCTOGGLEHDR		_IOW('K', 0, u_int)   /* turn headers on/off */
#define KUEIOCHDRSTATUS		_IOR('K', 1, u_int)   /* are headers on ? */

#include "kue_linux.ext"

#endif /* KUE_LINUX_H */
