/* $Id: remap_bmap.c,v 1.8 2000/08/16 13:24:26 proff Exp $
 * $Copyright:$
 */

#include <err.h>

#include "assert.h"
#include "maru.h"
#include "client_common.h"
#include "remap.h"

#include "remap_bmap.h"

static m_u32 BFREE = 0xffffffff;

struct remapBmapAspect
{
    m_u32 *map;		/* kept in network byte order */
    maruKeymapAspectRemap *keymap;
    int changes_outstanding;
};

struct remapBmapInstance
{
    maruSmap *smap;
    m_u32 free_blocks;
    int total_outstanding;
    maruRemapFlags remap_flags;
};

static bool
bmap_isset(struct remapBmapInstance *bi, m_u32 block)
{
    return SMAP_ISSET(bi->smap, block);
}

static bool
bmap_set(struct remapBmapInstance *bi, m_u32 block)
{
    return SMAP_SET(bi->smap, block);
}

inline static bool
bmap_clr(struct remapBmapInstance *bi, m_u32 block)
{
    return SMAP_CLR(bi->smap, block);
}

static m_u32
bmap_findfree(struct remapBmapInstance *imap, m_u32 blocks)
{
    m_u32 r;
    m_u32 n;
    if (imap->free_blocks<1)
	{
	    warnx("no free blocks");
	    return (m_u32)-1;
	}
    /* pick block at random */
    for (n=0; n<32; n++)
	{
	    r = maruRandom32()%blocks;
	    if (!bmap_isset(imap, r))
		return r;
	}
    /* pick a free block at random. examines n/2 blocks on average.
       note that the `obvious' and efficient method of simply hunting
       left or right for the next free block is *not* random and
       consequently *not* deniable */
    r = maruRandom32()%imap->free_blocks + 1;
    for (n=blocks; n--; )
	if (!bmap_isset(imap, n) && (--r == 0))
	    break;
    assert(r==0);
    return n;
}

static char *
bmap_make_inverse(maruInstance *i)
{
    char *s=maruCalloc(i->blocks);
    int as;
    for (as=0; as < i->aspects; as++)
	{
	    int n;
	    maruAspect *a = i->aspect[as];
	    if (!a)
		continue;
	    for (n=0; n<a->blocks; n++)
		{
		    m_u32 m;
		    struct remapBmapAspect *ba;
		    ba = a->remapAspectCtx;
		    if (ba->map[n] == BFREE)
			continue;
		    m = ntoh32(ba->map[n]);
		    if (s[m])
			s[m] = '*'; /* collision */
		    else
			s[m] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ?"[MIN(10+26+26, as)];
		}
	}
    return s;
}

static void
bmap_printsmap(maruInstance *i)
{
    struct remapBampInstance *bi = i->remapInstanceCtx;
    int n;
    char *inv;
    assert(bi);
    inv = bmap_make_inverse(i);
    for (n=0; n < i->blocks; n++)
	{
	    if (n%70==0)
		{
		    if (n!=0)
			printf("\n");
		    printf("%x\t", n);
		}
	    printf("%c", inv[n]? inv[n]: '.');
	}
    printf("\n");
    maruWipeFree(inv);
}

static m_u32
bmap_alloc(maruAspect *a, struct remapBmapInstance *bi, struct remapBmapAspect  *ba, m_u32 block)
{
    m_u32 newblock;
    assert(block < a->blocks);
    newblock = bmap_findfree(bi, a->instance->blocks);
    if (newblock == (m_u32)-1)
	return newblock;
    assert(ba->map[block] == BFREE);
    assert(!bmap_isset(bi, newblock));
    ba->map[block] = hton32(newblock);
    ba->changes_outstanding++;
    bi->total_outstanding++;
    bmap_set(bi, newblock);
    bi->free_blocks--;
    assert(bi->free_blocks>=0);
    return newblock;
}

static void
bmap_free(struct remapBmapInstance *bi, struct remapBmapAspect *ba, m_u32 block)
{
    if (ba->map[block] != BFREE)
	{
	    m_u32 b = ntoh32(ba->map[block]);
	    ba->map[block] = BFREE;
	    assert(bmap_isset(bi, b));
	    bmap_clr(bi, b);
	    bi->free_blocks++;
	    ba->changes_outstanding++;
	    bi->total_outstanding++;
	}
}

static void
bmap_mapToSmap(struct remapBmapInstance *bi, struct remapBmapAspect *ba, m_u32 blocks)
{
    m_u32 n;
    m_u32 dups=0;
    for (n=0; n<blocks; n++)
	if (ba->map[n] != BFREE)
	    {
		m_u32 b = ntoh32(ba->map[n]);
		if (bmap_isset(bi, b))
		    {
			dups++;
		    }
		else
		    {
			bmap_set(bi, b);
			bi->free_blocks--;
		    }
	    }
    if (dups>0)
	warnx("warning, newly added aspect has blocks in common with existing aspects!");
    assert(bi->free_blocks>=0);
}

EXPORT m_u32 maruRemapBmapSize(m_u32 blocks)
{
    struct maruRemapBmapKeymap_st bmap;
    return (char*)&bmap.remap[blocks] - (char*)&bmap;
}

EXPORT maruKeymapAspectRemap* maruRemapBmapCreate(maruInstance *i, m_u32 blocks, int *lenp, maruRemapFlags remap_flags)
{
    int len = maruRemapBmapSize(i->aspect_blocks);
    maruKeymapAspectRemap *r = maruCalloc(len);
    int n;
    for (n=0; n < i->aspect_blocks; n++)
	r->bmap.remap[n] = BFREE;
    *lenp = len;
    return r;
}

EXPORT void* maruRemapBmapNew(maruInstance *i, maruRemapFlags remap_flags)
{
    struct remapBmapInstance *bi = maruCalloc(sizeof *bi);
    bi->smap = maruCalloc(i->blocks / 8);
    bi->free_blocks = i->blocks;
    bi->remap_flags = remap_flags;
    return bi;
}

static void
bmap_keymapToMap(struct remapBmapAspect *ba, m_u32 blocks)
{
    int n;
    for (n=0; n < blocks; n++)
	ba->map[n] = ba->keymap->bmap.remap[n];
}

static void
bmap_mapToKeymap(struct remapBmapAspect *ba, m_u32 blocks)
{
    int n;
    for (n=0; n < blocks; n++)
	ba->keymap->bmap.remap[n] = ba->map[n];
}

EXPORT void* maruRemapBmapAddAspect(maruAspect *a, maruKeymapAspectRemap *hr)
{
    maruInstance *i = a->instance;
    struct remapBmapAspect *ba;
    struct remapBmapInstance *bi = i->remapInstanceCtx;
    assert(bi);
    ba = maruCalloc(sizeof *ba);
    ba->keymap = hr;
    ba->map = maruCalloc(a->blocks * sizeof(m_u32));
    bmap_keymapToMap(ba, a->blocks);
    bmap_mapToSmap(bi, ba, a->blocks);
    return ba;
}

EXPORT void maruRemapBmapReleaseAspect(maruAspect *a)
{
    m_u32 n;
    maruInstance *i = a->instance;
    struct remapBmapAspect *ba = a->remapAspectCtx;
    struct remapBmapInstance *bi = i->remapInstanceCtx;
    assert(bi);
    assert(ba);
    assert(ba->changes_outstanding == 0);
	
    /* TODO option to disable prevent clearing of remap information? */
    for (n=0; n < a->blocks; n++)
	if (ba->map[n] != BFREE)
	    {
		m_u32 b = ntoh32(ba->map[n]);
		if (bmap_isset(bi, b))
		    {
			bmap_clr(bi, b);
			bi->free_blocks++;
		    }
	    }
    assert(bi->free_blocks<=i->blocks);
    maruWipeFree(ba->map);
    maruWipeFree(ba);
    a->remapAspectCtx = NULL;
#warning save updated remap
}

EXPORT void maruRemapBmapFree(maruInstance *i)
{
    int n;
    struct remapBmapInstance *bi = i->remapInstanceCtx;
    for (n=0; n<i->aspects; n++)
	if (i->aspect[n])
	    maruRemapBmapReleaseAspect(i->aspect[n]);
    assert(bi->total_outstanding == 0);
    maruWipeFree(bi->smap);
    maruFree(bi);
    i->remapInstanceCtx = NULL;
}

EXPORT bool maruRemapBmapMapIO(maruReq *req)
{
    maruAspect *a = req->aspect;
    maruInstance *i = a->instance;
    struct remapBmapInstance *bi = i->remapInstanceCtx;
    struct remapBmapAspect *ba = a->remapAspectCtx;
    assert(bi);
    assert(ba);
    assert(req->block < a->blocks);
    switch (req->op)
	{
	case MR_READ:
	    if (ba->map[req->block] == BFREE)
		{
		    return maruBlockIoReadZeros(req);
		}
	    else
		{
		    req->block = ntoh32(ba->map[req->block]);
		}
	    break;
	case  MR_WRITE:
	    if (isZero(req->data, req->blockSize))
		{
		    bmap_free(bi, ba, req->block);
		    return maruBlockIoWriteNothing(req);
		}
	    else
		{
		    bool balloc;
		    if (ba->map[req->block] == BFREE)
			balloc = TRUE;
		    else
			{
			    if (!(bi->remap_flags&RF_DISABLE_REALLOC))
				{
				    bmap_free(bi, ba, req->block);
				    balloc = TRUE;
				}
			    else
				balloc = FALSE;
			}
		    if (balloc)
			{
			    m_u32 t = bmap_alloc(a, bi, ba, req->block);
			    if (t == (m_u32)-1)
				return FALSE;
			    req->block = t;
			}
		    else
			req->block = ntoh32(ba->map[req->block]);
		}
	    break;
	}
    return maruBlockIo(req);
}

EXPORT void maruRemapBmapInfo(maruInstance *i, int as, maruRemapInfoFlag flag)
{
    switch(flag)
	{
	case I_INSTANCE:
	case I_ASPECT:
	    printf("Block -> Aspect ownership map (* = collision):\n");
	    bmap_printsmap(i);
	    break;
	}
}

EXPORT bool maruRemapBmapSync(maruInstance *i)
{
    struct remapBmapInstance *bi = i->remapInstanceCtx;
    int n;
    if (bi->total_outstanding < 1)
	return FALSE;
    for (n=0; n < i->aspects; n++)
	if (i->aspect[n])
	    {
		maruAspect *a = i->aspect[n];
		struct remapBmapAspect *ba = a->remapAspectCtx;
		if (ba->changes_outstanding > 0)
		    {
			bmap_mapToKeymap(ba, a->blocks);
			bi->total_outstanding -= ba->changes_outstanding;
			ba->changes_outstanding = 0;
		    }
	    }
    assert (bi->total_outstanding == 0);
    return TRUE;
}
