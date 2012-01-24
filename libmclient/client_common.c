/* $Id: client_common.c,v 1.32 2000/08/17 11:11:25 proff Exp $
 * $Copyright:$
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <paths.h>
#include <err.h>
#include <signal.h>
#include <sys/types.h>
#include <utime.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "maru_types.h"
#include "libproff.h"
#include "maru.h"
#include "ciphers.h"
#include "remap.h"

#include "libmclient.h"

EXPORT int a_debug = 1;		/* debug level, 0 = quiet, 1 = normal, 2 = debug */
EXPORT int a_force = 0; 	/* continue despite errors */
EXPORT volatile char *stackP = NULL;	/* pointer to stack at main, when set activates various memory erasure routines */

struct wipeList
{
    struct wipeList *next;
    void *data;
    int len;
} *wipeList = NULL;

EXPORT void freeWipeList(bool nofree)
{
    struct wipeList *wl;
    for (wl = wipeList; wl; wl=wl->next)
	maruWipe(wl->data, wl->len);
    /* these are seperate to prevent curruption of
         malloc tables faulting the erasure loop */
    for (wl = wipeList; wl; wl=wl->next)
	{
	    xmunlock(wl->data, wl->len);
	    if (!nofree)
		{
		    free(wl->data);
		    free(wl);
		}
	}
}

EXPORT void *maruMalloc(int len)
{
    struct wipeList *wl;
    void *p = xmalloc(len);
    xmlock(p, len);
    wl = xmalloc(sizeof *wl);
    wl->data = p;
    wl->len = len;
    wl->next = wipeList;
    wipeList = wl;
    return p;
}

EXPORT void *maruCalloc(int len)
{
    void *p;
    p = maruMalloc(len);
    if (p)
	bzero(p, len);
    return p;
}

EXPORT void maruFree(void *p)
{
    struct wipeList *wl, *wp = NULL;
    for (wl = wipeList; wl; wp = wl, wl=wl->next)
	if (wl->data == p)
	    goto found;
    {
	char msg[] = "maruFree() failed to find allocation in wipeList\n";
	write(2, msg, sizeof(msg)-1);
	return;
    }
 found:
    if (wp)
	wp->next = wl->next;
    else
	wipeList = wl->next;
    xmunlock(p, wl->len);
    free(p);
}

EXPORT void maruWipeFree(void *p)
{
    struct wipeList *wl, *wp = NULL;
    for (wl = wipeList; wl; wp = wl, wl=wl->next)
	if (wl->data == p)
	    goto found;
    {
	char msg[] = "maruWipeFree() failed to find allocation in wipeList\n";
	write(2, msg, sizeof(msg)-1);
	return;
    }
 found:
    if (wp)
	wp->next = wl->next;
    else
	wipeList = wl->next;
    maruWipe(p, wl->len);
    xmunlock(p, wl->len);
    free(p);
}

EXPORT int matoi(char *s)
{
    int i;
    if (sscanf(s, "%i", &i) != 1)
	return -1;
    return i;
}

EXPORT int xmatoi(char *s)
{
    int i = matoi(s);
    if (i<0)
	errx(1, "Look Harold \"%s\" must be one of those new Cantegers!", s);
    return i;
}

/* not meant to be fast or secure, should be endian independant however */

EXPORT m_u32 simpleSum(u_char *p, int len)
{
    m_u32 n;
    m_u32 sum = 0;
    for (n=0; n<len; n++)
	sum = ((sum<<9)^(sum>>23))+((m_u32)(p[n])^n);
    return sum;
}

EXPORT bool waitForEntropy = TRUE;


EXPORT void maruRandom(void *buf, int n, maru_random type, void (*statusCallback)(int,int,int))
{
    int i;
    char *fn;
    char *p = buf;
    int fd;
    if (!waitForEntropy)
	type = RAND_PSEUDO;
    fn = (type == RAND_PSEUDO)? _PATH_URANDOM : _PATH_RANDOM;
    fd = open(fn, O_RDONLY);
    if (fd<0)
	err(1, "%s", fn);
    for (i=0; i<n;)
	{
	    int cc;
	again:
	    if (fd<0 || (cc = read(fd, p+i, n-i))<0)
		{
		    if (errno == EINTR)
			goto again;
		    err(1, fn);
		}
	    i += cc;
	    if (statusCallback && cc>0)
		statusCallback(n, i, cc);
	    if (i<n)
		usleep(100); /* let /dev/random generate a few more bits of entropy */
	}
    Iam1970(fn);
    close(fd);
}

#define RANDPOOLSIZE 256

/* --rpw XXX 19990905 optimization needed here */
EXPORT m_u32 maruRandom32()
{
    static m_u32 buf[RANDPOOLSIZE];
    static int n = 0, high = 0;
    if (n >= high/(sizeof(m_u32)))
	{
	    int fd;
	    n=0;
	    if (high>=sizeof(m_u32))
		high=0;
	    if ((fd = open(_PATH_URANDOM, O_RDONLY)) < 0)
		err(1, "%s", _PATH_URANDOM);
	    while (high < sizeof(m_u32))
		{
		    int cc;
		again:
		    if ((cc = read(fd, (char*)buf+high, sizeof(buf)-high)) < 1)
			{
			    if (errno == EINTR)
				goto again;
			    err(1, "%s", _PATH_URANDOM);
			}
		    high+=cc;
		}
	    Iam1970(_PATH_URANDOM);
	    close(fd);   
    }
    return buf[n++];
}

static void
rand_status(int max, int n, int cc)
{
    if (a_debug>0)
	{
	    int m = (float)cc/max * 40.0;
	    int y;
	    for (y=0; y<m; y++)
		fprintf(stderr, ".");
	    fflush(stderr);
	}
}

EXPORT void maruRandomf(void *data, int len, maru_random type, char *fmt, ...) EXP_(__attribute__ ((format (printf, 4, 5))))
{
  va_list ap;
  va_start(ap, fmt);
  if (a_debug>0)
    {
      printf("Generating %d %scryptographically random bytes for ", len, (type == RAND_PSEUDO)? "pseudo-": "");
      vprintf(fmt, ap);
      printf("\n");
      fflush(stdout);
    }
  maruRandom(data, len, type, rand_status);
  if (a_debug>0)
    {
      printf("\n");
      fflush(stdout);
    }
}

EXPORT bool f_wipeMem = TRUE;

EXPORT void maruWipe(void *p, int n)
{
    int i;
    int j;
    char *buf = p;
    if (!f_wipeMem)
	return;
    for (i=0; i<n; i++)
	buf[i]^=0xff;
    usleep(20);
    for (j=0; j<40; j++)
	{
	    for (i=0; i<n; i++)
		buf[i]^=0xff;
	}
    for (j=0; j<2; j++)
	    maruRandom(buf, n, RAND_PSEUDO, NULL);
}

EXPORT u_char *loadFile(char *name, int *len)
{
    struct stat st;
    char *p;
    int fd = open(name, O_RDONLY);
    if (fd<0 ||	fstat(fd, &st) !=0)
	err(1, name);
    p = xmalloc(st.st_size);
    if (read(fd, p, st.st_size)!=st.st_size)
	err(1, name);
    Iam1970(name);
    close(fd);
    *len = st.st_size;
    return p;
}

EXPORT maruKeymap *loadKeymap(char *name, int *klenp)
{
    int len;
    maruKeymap *h = (maruKeymap*)loadFile(name, &len);
    if (len < sizeof *h)
	errx(1, "invalid maru keymap length (%d vs min %d)\n", len, sizeof *h);
    if (!validKeymap(h, len) && !a_force)
	exit(1);
    *klenp = len;
    return h;
}

EXPORT void makeKeymapSum(maruKeymap *h, int len)
{
    h->headSum = hton32(0);
    h->headSum = hton32(simpleSum((u_char*)h, len));
}

EXPORT void saveKeymap(char *name, maruKeymap *h, int len)
{
    int fd = open(name, O_WRONLY|O_TRUNC|O_CREAT, 0600);
    if (fd<0)
	err(1, name);
    h->headSum = hton32(0);
    h->headSum = hton32(simpleSum((u_char*)h, len));
    if (write(fd, h, len)!=len)
	err(1, name);
    Iam1970(name);
    fsync(fd);
    close(fd);
}

EXPORT void syncInstance(maruInstance *i)
{
    if (i->remapDesc->sync && i->remapDesc->sync(i))
	{
	    makeKeymapSum(i->keymap, i->keymap_len);
	    if (lseek(i->keymap_fd, 0, SEEK_SET) == 0)
		{
		    if (write(i->keymap_fd, i->keymap, i->keymap_len) != i->keymap_len)
			warn("syncInstance(): problems writing to keymap");
		}
	    else
		warn("syncInstance: problems lseeking keymap");
	}
}

EXPORT void freeInstance(maruInstance *i)
{
    int n;
    syncInstance(i);
    if (i->remapDesc->free)
	i->remapDesc->free(i);
    i->remapInstanceCtx = NULL;
    for (n=0; n < i->aspects; n++)
	if (i->aspect[n])
	    {
		freeAspect(i->aspect[n]);
		i->aspect[n] = NULL;
	    }
    maruWipeFree(i->aspect);
    maruWipeFree(i);
}

EXPORT NORETURN void wipeStackExit() /* mmm, brutal */
{
    char sp;
    /* we handle both up and down growing stacks */
    maruWipe(MIN(&sp, (char*)stackP), (char *)MAX(&sp, (char*)stackP) - (char*)MIN(&sp, (char*)stackP));
    _exit(1);
}

EXPORT void freeAspect(maruAspect *a)
{
    int n;
    maruInstance *i=a->instance;
    if (a->remapAspectCtx && i->remapDesc->releaseAspect)
	i->remapDesc->releaseAspect(a);
    a->remapAspectCtx = NULL;
    if (a->keyOpaque)
	maruWipeFree(a->keyOpaque);
    for (n=0; n<2; n++)
	if (a->latticeOpaque[n])
	    maruWipeFree(a->latticeOpaque[n]);
    if (a->blockOpaque)
	maruWipeFree(a->blockOpaque);
    if (a->lattice)
	maruWipeFree(a->lattice);
    if (a->whitener)
	maruWipeFree(a->whitener);
    i->aspect[a->aspect_num] = NULL;
    maruWipeFree(a);
}

/*
 * build a maruAspect and associated structures
 * caller is responsible for freeing the aspect (and child structures) via freeAspect()
 *
 * parameter key is wiped
 */

EXPORT maruAspect *buildAspect(maruInstance *i, maruKeymapAspect *h, int as, maruPass *key, int keylen)
{
    maruCipherDesc *c1;
    int n;
    int iterations;
    m_u64 *mk;
    maruAspect *a;
    maruOpaque *info_ctx = NULL;
    maruOpaque *remap_ctx = NULL;

    SECURE
    {
	maruCycle cycle;
	int keylen;
	maruPass pass;
	maruKey latticeKey[2];
        maruKey remapKey;
	maruAspectInfo info;
    } END_SECURE(s);

    a = maruCalloc(sizeof *a);
    a->aspect_num = as;
    /*
     * decode cipher types and allocate opaques
     */
    a->instance = i;
    c1 = i->keyCipher;
    a->keyOpaque = maruOpaqueInit(c1);
    s->keylen = c1->keylen? c1->keylen: sizeof (s->pass);
    /* apply pass salt */
    memcpy(&s->pass, &h->passSalt, sizeof s->pass);
    xor(&s->pass, key, keylen);
    maruWipe(key, keylen);
    c1->setkey(a->keyOpaque, s->pass.data, s->keylen, MCD_DECRYPT);
    maruWipe(&s->pass, sizeof s->pass);
    iterations = i->iterations;
    if (a_debug>0)
	{
	    printf("Agitating master key with %s key generator over %d iterations...\n", c1->txt, iterations);
	    fflush(stdout);
	}
    /* decrypt/agitate master key */
    memcpy(&s->cycle, &h->cycle, sizeof s->cycle);
    /* beware! understand this algorithm fully before the slightest change */
    mk = (m_u64*)&s->cycle;
    while (iterations-->0)
	{
	    c1->crypt(a->keyOpaque, NULL,
		      (u_char*)&s->cycle, (u_char*)&s->cycle, sizeof s->cycle, MCD_DECRYPT);
	    if (c1->blocksize)	/* only chain block ciphers */
		mk[0] ^= mk[sizeof(s->cycle)/sizeof(m_u64) - 1]; /* XXX presumptive! */
	}
    xor(&s->cycle, &h->cycleSalt, sizeof s->cycle);
    if (a_debug>1)
	printf("masterKey[0..8] = 0x%qx\n", *(m_u64*)&s->cycle.masterKey);
    if (s->cycle.keySum[0] != s->cycle.keySum[1])
        {
	    freeAspect(a);
	    a = NULL;
	    goto ex;
        }
    /* use the master key from now on */
    c1->setkey(a->keyOpaque, (char*)&s->cycle.masterKey, sizeof s->cycle.masterKey, MCD_ENCRYPT);
    maruWipe(&s->cycle.masterKey, sizeof s->cycle.masterKey);

    info_ctx = maruOpaqueInit(c1);
    if (a_debug>1)
	printf("infoKey[0..8] = 0x%qx\n", *(m_u64*)&s->cycle.infoKey);
    c1->setkey(info_ctx, s->cycle.infoKey.data, sizeof s->cycle.infoKey, MCD_DECRYPT);
    c1->crypt(info_ctx, NULL, (char *)&h->info, (char *)&s->info, sizeof s->info, MCD_DECRYPT);
    xor(&s->info, &h->infoSalt, sizeof h->infoSalt);
    
    a->start = ntoh32(s->info.start);
    a->blocks = ntoh32(s->info.blocks);
    /* set cipher types and allocate opaques */
    a->latticeCipher = xfindCipherType(ntoh8(s->info.latticeCipherType));
    for (n=0; n<2; n++)
	    a->latticeOpaque[n] = maruOpaqueInit(a->latticeCipher);
    a->blockCipher = xfindCipherType(ntoh8(s->info.blockCipherType));
    a->blockOpaque = maruOpaqueInit(a->blockCipher);
    /* allocate lattice */
    a->lattice_len = MIN(EITHER(a->blockCipher->keylen, sizeof(maruKey)), sizeof(maruKey)) * 2 * i->depth;
    a->lattice = maruCalloc(a->lattice_len);
    /* allocate blockIV */
    a->whitener = maruCalloc(i->blockSize);
    /* create the two independent lattice keys */
    memcpy(s->latticeKey, h->latticeKeySalt, sizeof s->latticeKey);
    c1->crypt(a->keyOpaque, NULL, (u_char*)&s->latticeKey, (u_char*)&s->latticeKey, sizeof s->latticeKey, MCD_ENCRYPT);
    a->latticeCipher->setkey(a->latticeOpaque[0], (u_char*)&s->latticeKey[0], sizeof (s->latticeKey[0]), MCD_ENCRYPT);
    /* the right direction of the lattice uses MCD_DECRYPT, to prevent attacks on ciphers that are groups */
    /* --rpw XXX huh ?!? your cipher shouldn't be a group ! */
    /* --proff but what if it *is* a group anyway? And a cipher can still have group properties *some* of
               the time, without formally being a group */
    a->latticeCipher->setkey(a->latticeOpaque[1], (u_char*)&s->latticeKey[1], sizeof(s->latticeKey[1]), MCD_DECRYPT);
    /* throw away the pre-key-scheduled lattice keys */
    maruWipe(&s->latticeKey, sizeof s->latticeKey);
    /* pull in (public) IV's (or salts if you prefer) for the entire lattice */
    memcpy(a->lattice, h->latticeSalt, a->lattice_len);
    /* create the lattice key-necklace */
    c1->crypt(a->keyOpaque, NULL, a->lattice, a->lattice, a->lattice_len, MCD_ENCRYPT);
    /* create the block whitener */
    memcpy(a->whitener, h->whitener, i->blockSize);
    c1->crypt(a->keyOpaque, NULL, a->whitener, a->whitener, i->blockSize, MCD_ENCRYPT);
#warning todo remap
#if 0
    a->remap = maruMalloc(sizeof (m_u32) * MAX_SPLITS);
    c1->crypt(a->keyOpaque, NULL, (char*)&h->remapKey, (char*)&s->remapKey, sizeof s->remapKey, MCD_ENCRYPT);
    c3->setkey(remap_opaque, (char*)&s->remapKey, sizeof s->remapKey, MCD_DECRYPT);
    memcpy(a->remap, h->remap, sizeof(m_u32) * MAX_SPLITS);
    c3->crypt(remap_opaque, h->a->remap, h->remap, sizeof h->remap);
    for(n = 0; n < MAX_SPLITS; n++)
	{
	    if (a->remap[n] == (m_u32) -1)
		continue;
	    if (SMAP_ISSET(i->smap, a->remap[n]))
		fprintf(stderr, "duplicate moby-block allocation (%u) !\n", a->remap[n]);
	    SMAP_SET(i->smap , a->remap[n]);
	}
#endif
    if (i->remapDesc->addAspect)
	a->remapAspectCtx = i->remapDesc->addAspect(a, &h->remap);
ex:
    if (info_ctx)
        maruWipeFree(info_ctx);
    /* we don't use the key cipher elsewhere */
    if (a)
	{
	    maruWipeFree(a->keyOpaque);
	    a->keyOpaque = NULL;
	}
    maruWipeFree(s);
    return a;
}

EXPORT bool validKeymap(maruKeymap *h, int len)
{
    m_u32 sum, sum2;

    if (ntoh8(h->majVersion) != MH_MAJ_VERSION)
	{
	    warnx("maru keymap major version %d != %d (evidentially your marutukku is no longer as trendy as you may have hoped))", h->majVersion, MH_MAJ_VERSION);
	    return FALSE;
	}    
    if (ntoh8(h->minVersion) != MH_MIN_VERSION)
	warnx("maru keymap has major version %d, minor version %d but we desire major version %d, minor version %d. A clock chimes softly.", h->majVersion, h->minVersion, MH_MAJ_VERSION, MH_MIN_VERSION);
    sum = h->headSum;
    h->headSum = hton32(0);
    sum2 = hton32(simpleSum((u_char*)h, len));
    h->headSum = sum;
    if (sum != sum2)
	{
	    warnx("maru keymap checksum 0x%x != calculated checksum of 0x%x. you look very downcast and start humming :wumpskut:", sum, sum2);
	    return FALSE;
	} 
    return TRUE;
}

EXPORT maruInstance *instanceNew(maruKeymap *h, int klen, maruRemapFlags remap_flags)
{
   maruInstance *i;
   if (!validKeymap(h, klen) && !a_force)
	exit(1);
    i = maruCalloc(sizeof *i);
    i->keymap = h;
    i->keymap_len = klen;
    i->blockSize = ntoh32(h->blockSize);
    i->depth = ntoh32(h->depth);
    i->keyCipher = xfindCipherType(h->keyCipherType);
    i->iterations = ntoh32(h->iterations); /* filled in by the call to buildAspect */
    if (!(i->remapDesc = remapLookupType(ntoh8(h->remapType))))
	errx(1, "unsupported remapping type %d", ntoh8(h->remapType));
    i->blocks = ntoh32(h->blocks);
    i->aspect_blocks = ntoh32(h->blocks);
    i->aspects = ntoh32(h->aspects);
    i->aspect = maruCalloc(i->aspects * sizeof (maruAspect *));
    if (i->remapDesc->new)
	i->remapInstanceCtx = i->remapDesc->new(i, remap_flags);
    return i;
}

EXPORT maruAspect *getAspect(maruInstance *i, int as)
{
    if (as >= i->aspects)
	errx(1, "invalid aspect %d (specified aspect should be in the range 0 - %d)", as, i->aspects);
    if (!i->aspect[as])
	errx(1, "aspect %d does not exist", as);
    return i->aspect[as];
}
 
EXPORT int getKeymapAspectLen(maruInstance *i)
{
    int len = sizeof (maruKeymapAspect);
    if (i->remapDesc->size)
	len += i->remapDesc->size(i->aspect_blocks) - sizeof(maruKeymapAspectRemap);
    return len;
}

EXPORT maruKeymapAspect *getKeymapAspect(maruInstance *i, maruKeymap *keymap, int as)
{
    return
	(maruKeymapAspect*)
	((char*)&keymap->aspect[0] +
	 getKeymapAspectLen(i) * as);
}

EXPORT maruInstance *genInstance(char *fn, maruRemapFlags remap_flags)
{
    maruInstance *i;
    maruKeymap *h;
    int n;
    int klen;
    SECURE
      {
	int passlen;
	maruPass pass;
      }
    END_SECURE(s);

    h = loadKeymap(fn, &klen);
    i = instanceNew(h, klen, remap_flags);

    if ((i->keymap_fd = open(fn, O_WRONLY)) < 0)
	err(1, "couldn't open '%s' for write", fn);

    for (n=0; n < i->aspects; n++)
	{
	    maruAspect *a;
	    char prompt[64];
	    sprintf(prompt, "Aspect %d passphrase (\".\" to end): ", n);
	    if ((s->passlen = asGetPassPhrase(n, prompt, &s->pass)) < MIN_PASSPHRASE
		|| !(a=buildAspect(i, getKeymapAspect(i, h, n), n, &s->pass, s->passlen)))
		{
		    if (strcmp(s->pass.data, ".") == 0)
			break;
		    if (s->pass.data[0] != '\0')
			{
			    fprintf(stderr, "Aspect %d non-existant, or incorrect passphrase\n", n);
			    n--;
			}
		    continue;
		}
	    i->aspect[n] = a;
	}
    maruWipeFree(s);
    return i;
}


EXPORT void listCiphers(FILE *fh)
{
    maruCipherDesc *c;
    for (c = m_ciphers; c->txt; c++)
	{
	    fprintf(fh, "%s%s:\n\tType: %s\n\tKeylen: %d\n\tBlocksize: %d\n\tState_size: %d\n",

		    (c==m_ciphers)? "": "\n", c->txt, c->blocksize? "Stream": "Block",
		    c->keylen? c->keylen: MAX_PASSPHRASE,
		    c->blocksize, c->opaque_size);
	}
}

EXPORT maruCipherDesc *xfindCipherTxt(char *txt)
{
    maruCipherDesc *c = findCipherTxt(txt);
    if (!c)
	    errx(1, "Cipher type \"%s\" unavailable.", txt);
    return c;
}

EXPORT maruCipherDesc *xfindCipherType(maruCipher cipher)
{
    maruCipherDesc *c = findCipherType(cipher);
    if (!c)
	    errx(1, "Cipher type \"%d\" unavailable.", cipher);
    return c;
}

EXPORT void nocore()
{
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rl)!=0)
	warn("couldn't set core limits to zero");
}

static void sighand(int sig)
{
    /* don't call any malloc()ing function here on in, we may have SIGSEGV'd due to corruption of malloc() tables */
    char msg[] = "caught fatal signal. scorched earth policy entered into for possible memory resident key artifacts (may take some time)\n";
    signal(SIGSEGV, SIG_DFL); /* prevent sigsegv loops */
    write (2, msg, sizeof(msg)-1);
    freeWipeList(TRUE);
    wipeStackExit();
    /* NOT REACHED */
}

EXPORT void maruExitHandler()
{
    if (stackP)
	{
	    freeWipeList(FALSE);
	    wipeStackExit();
	    /* NOT REACHED */
	}
}

static int oksig[] =
{
#ifdef SIGSTOP
    SIGSTOP,
#endif
#ifdef SIGTSTP
    SIGTSTP,
#endif
#ifdef SIGCONT
    SIGCONT,
#endif    
#ifdef SIGTTIN
    SIGTTIN,
#endif
#ifdef SIGTTOU
    SIGTTOU,
#endif
#ifdef SIGWINCH
    SIGWINCH,
#endif
#ifdef SIGINFO
    SIGINFO,
#endif      
    -1
};

EXPORT void nosignals()
{
    int n;
    for (n=0; n<SIGUSR2+1; n++)
	{
	    int i;
	    void *p;
	    for (i=0; oksig[i]!=-1; i++)
		if (oksig[i] == n)
		    goto skip;
	    p = signal(n, sighand);
	    if (p == SIG_IGN)
		signal(n, p);
	skip:
	    ;
	}
}

EXPORT bool f_timestampHack = TRUE;

EXPORT int Iam1970(char *fn)
{
    if (f_timestampHack)
	{
	    struct utimbuf ut;
	    ut.actime = 0;
	    ut.modtime = 0;
	    return utime(fn, &ut);
	}
    return 0;
}
