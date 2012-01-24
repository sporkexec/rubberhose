/* $Id: common.c,v 1.2 2000/04/20 03:01:17 proff Exp $
 * $Copyright:$
 */

#include <stdio.h>
#include <string.h>

#include "maru.h"
#include "common.h"
#include "ciphers.h"
#include "assert.h"

extern void *maruWipeFree(void *opaque);
extern void *maruCalloc(int len);

EXPORT void *maruOpaqueInit(maruCipherDesc *cipher)
{
    void *p = maruCalloc(cipher->opaque_size);
    if (!p)
	return NULL;
    cipher->init(cipher, p, 0);
    return p;
}

EXPORT void maruOpaqueFree(void *opaque)
{
    maruWipeFree(opaque);
}

EXPORT void xor(void *vp, void *vp1, int len)
{
    int n;
    char *p = vp;
    char *p1 = vp1;
    for (n=0; n<len; n++)
	p[n]^=p1[n];
}

void static inline xor64(m_u64 *p, m_u64 *p1, int len)
{
    int n;

    len/=8;
    for (n = 0; n<len; n++)
	p[n]^=p1[n];
}

/* --rpw XXX unused code. scrap if really no longer needed */
#if 0
/* XXX verify endian independance 
 *
 * p xor p1 -> p
 *
 * this is fast and stupid checksum code. All we use it for is generating a unique iv.
 */ 

static m_u64 xor64sum(m_u64 *p, m_u64 *p1, int len)
{
    int n;
    m_u64 sum = 0;

    len/=8;
    for (n = 0; n<len; n++)
	{
	    p[n]^=p1[n];
	    sum+=p[n];
	}
    return sum;
}

static void xor64to(m_u64 *p, m_u64 *p1, m_u64 *to, int len)
{
    int n;
    len/=8;
    for (n = 0; n < len; n++) 
	to[n] = p[n]^p1[n];
}

static m_u64 xor64sumTo(m_u64 *p, m_u64 *p1, m_u64 *to, int len)
{
    int n;
    m_u64 sum = 0;
    len/=8;
    for (n = 0; n < len; n++) 
	{
	    to[n] = p[n]^p1[n];
	    sum+=to[n];
	}
    return sum;
}
#endif

EXPORT void int2char(m_u32 i, u_char *p)
{
    p[3] = i;
    p[2] = i>>8;
    p[1] = i>>16;
    p[0] = i>>24;
}

EXPORT m_u32 char2int(u_char *p)
{
    return p[3] | (p[2]<<8) | (p[1] << 16) | (p[0] <<24);
}

EXPORT maruCipherDesc *findCipherType(maruCipher cipher)
{
    maruCipherDesc *m = m_ciphers;
    for (; m->cipher != m_none; m++)
	if (m->cipher == cipher)
	    return m;
    return NULL;
}

EXPORT maruCipherDesc *findCipherTxt(char *txt)
{
    maruCipherDesc *m = m_ciphers;
    for (; m->cipher != m_none; m++)
	if (strcmp(m->txt, txt) == 0)
	    return m;
    return NULL;
}

EXPORT void maruGenBlockKey(maruAspect *a, maruKey *key, int keylen, m_u32 blockno)
{
    int n;
    m_u32 dm = (m_u32)1 << (a->instance->depth-1);
    assert(keylen >= sizeof(m_u64));
    bzero(key, keylen);
    /* We no-longer use the cachable method, as we can get some extra security by using the block no as an iv, at the
     * "expense" of non-predictability in similar msb runs */
    *(m_u32*)key = hton32(blockno);
    /* this is really just a log2, to find the leftmost set bit */
    for (n=0,blockno++;!(blockno & dm); blockno<<=1, n++) {} /* XXX verify behavior for block # 2^32-1 */
    for (n=a->instance->depth-n; n>0; blockno<<=1, n--)
	{
	    int x = !(blockno & dm);
	    xor64((m_u64*)key, (m_u64*)&a->lattice[(n*2+x)*keylen], keylen);
	    a->latticeCipher->crypt(a->latticeOpaque[x], NULL, key->data, key->data, keylen, x? MCD_DECRYPT: MCD_ENCRYPT);
	}
}

/* --rpw fix: maruEncryptBlock was broken for block != to */
EXPORT void maruEncryptBlock(maruAspect *a, u_char *block, u_char *to, int len, m_u32 blockno, int flags)
{
    maruKey key;
    m_u64 *block8 = (m_u64*)block,
	      *iv8 = (m_u64*)a->whitener,
	      *to8 = (m_u64*)to;

    int keysize;
    assert((a->blockCipher->blocksize == 0) || ((len%a->blockCipher->blocksize) == 0));
    keysize = MIN(sizeof key, EITHER(a->blockCipher->keylen, sizeof key)); /* XXX careful */
    assert((keysize&7) == 0);
    maruGenBlockKey(a, &key, keysize, blockno);
    a->blockCipher->setkey(a->blockOpaque, key.data, keysize, flags);
    if (flags & MCD_ENCRYPT)
	{
	    int n;
	    m_u64 sum = 0;

	    for (n=len/8; --n>0; )
		{
		    block8[n] ^= iv8[n];
		    sum ^= block8[n];
		}
	    block8[0] ^= sum ^ hton64(blockno);
	}
    a->blockCipher->crypt(a->blockOpaque, NULL /* do the iv's by hand */, block, to, len, flags);

    /* --rpw restore contents of original block */
    if (flags & MCD_ENCRYPT && block != to)
	{
	    int n;
	    m_u64 sum = 0;

	    for (n=len/8; --n>0; )
		{
		    sum ^= block8[n];
		    block8[n] ^= iv8[n];
		}
	    block8[0] ^= sum ^ hton64(blockno);
	}
    if (flags & MCD_DECRYPT)
	{
	    int n;
	    m_u64 sum = 0;

	    for (n=len/8; --n>0; )
		{
		    sum ^= to8[n];
		    to8[n] ^= iv8[n];
		}
	    to8[0] ^= sum ^ hton64(blockno);
	}
     bzero(&key, sizeof key);
}
