/* $Id: idea.c,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
#include "maru.h"
#include "assert.h"

#include "idea.h"
#include "idea_lcl.h"

#define midea_decrypt midea_encrypt
#define midea_decrypt_to midea_encrypt_to

/* len must be a multiple of 8 */


EXPORT void IDEAinit(maruCipherDesc *cipher, void *opaque, int flags)
{
}


static void IDEAsetkeyEnc(void *opaque, u_char *key, int len)
{
    mIDEA_KEY_SCHEDULE *ks = &((IDEAcontext *)opaque)->enc_ks;
    int i;
    register IDEA_INT *kt,*kf,r0,r1,r2;

    kt= &(ks->data[0][0]);
    n2s(key,kt[0]); n2s(key,kt[1]); n2s(key,kt[2]); n2s(key,kt[3]);
    n2s(key,kt[4]); n2s(key,kt[5]); n2s(key,kt[6]); n2s(key,kt[7]);
    
    kf=kt;
    kt+=8;
    for (i=0; i<6; i++)
	{
	    r2= kf[1];
	    r1= kf[2];
	    *(kt++)= ((r2<<9) | (r1>>7))&0xffff;
	    r0= kf[3];
	    *(kt++)= ((r1<<9) | (r0>>7))&0xffff;
	    r1= kf[4];
	    *(kt++)= ((r0<<9) | (r1>>7))&0xffff;
	    r0= kf[5];
	    *(kt++)= ((r1<<9) | (r0>>7))&0xffff;
	    r1= kf[6];
	    *(kt++)= ((r0<<9) | (r1>>7))&0xffff;
	    r0= kf[7];
	    *(kt++)= ((r1<<9) | (r0>>7))&0xffff;
	    r1= kf[0];
	    if (i >= 5) break;
	    *(kt++)= ((r0<<9) | (r1>>7))&0xffff;
	    *(kt++)= ((r1<<9) | (r2>>7))&0xffff;
	    kf+=8;
	}
}

static IDEA_INT inverse(m_u32 xin)
{
    m_32 n1,n2,q,r,b1,b2,t;
    
    if (xin == 0)
	b2=0;
    else
	{
	    n1=0x10001;
	    n2=xin;
	    b2=1;
	    b1=0;
	    
	    do	{
		r=(n1%n2);
		q=(n1-r)/n2;
		if (r == 0)
		    { if (b2 < 0) b2=0x10001+b2; }
		else
		    {
			n1=n2;
			n2=r;
			t=b2;
			b2=b1-q*b2;
			b1=t;
		    }
	    } while (r != 0);
	}
    return((IDEA_INT)b2);
}
 

static void midea_set_decrypt_key(mIDEA_KEY_SCHEDULE *ek, mIDEA_KEY_SCHEDULE *dk)
{
    int r;
    register IDEA_INT *fp,*tp,t;
    
    tp= &(dk->data[0][0]);
    fp= &(ek->data[8][0]);
    for (r=0; r<9; r++)
	{
	    *(tp++)=inverse(fp[0]);
	    *(tp++)=((int)(0x10000L-fp[2])&0xffff);
	    *(tp++)=((int)(0x10000L-fp[1])&0xffff);
	    *(tp++)=inverse(fp[3]);
	    if (r == 8) break;
	    fp-=6;
	    *(tp++)=fp[4];
	    *(tp++)=fp[5];
	}
    
    tp= &(dk->data[0][0]);
    t=tp[1];
    tp[1]=tp[2];
    tp[2]=t;
    
    t=tp[49];
    tp[49]=tp[50];
    tp[50]=t;
}

static void IDEAsetkeyDec(void *opaque, u_char *key, int len)
{
    IDEAcontext *c = (IDEAcontext *)opaque;
    IDEAsetkeyEnc(opaque, key, len);
    midea_set_decrypt_key(&c->enc_ks, &c->dec_ks);
}

static void midea_encrypt(m_u32 *d, mIDEA_KEY_SCHEDULE *key)
{
    int i;
    register IDEA_INT *p;
    register m_u32 x1,x2,x3,x4,t0,t1,ul;
    
    x2=d[0];
    x1=(x2>>16);
    x4=d[1];
    x3=(x4>>16);
    
    p= &(key->data[0][0]);
    for (i=0; i<8; i++)
	{
	    x1&=0xffff;
	    midea_mul(x1,x1,*p,ul); p++;
	    
	    x2+= *(p++);
	    x3+= *(p++);
	    
	    x4&=0xffff;
	    midea_mul(x4,x4,*p,ul); p++;
	    
	    t0=(x1^x3)&0xffff;
	    midea_mul(t0,t0,*p,ul); p++;
	    
	    t1=(t0+(x2^x4))&0xffff;
	    midea_mul(t1,t1,*p,ul); p++;
	    
	    t0+=t1;
	    
	    x1^=t1;
	    x4^=t0;
	    ul=x2^t0;		/* do the swap to x3 */
	    x2=x3^t1;
	    x3=ul;
	}
    
    x1&=0xffff;
    midea_mul(x1,x1,*p,ul); p++;
    
    t0= x3+ *(p++);
    t1= x2+ *(p++);
    
    x4&=0xffff;
    midea_mul(x4,x4,*p,ul);
    
    d[0]=(t0&0xffff)|((x1&0xffff)<<16);
    d[1]=(x4&0xffff)|((t1&0xffff)<<16);
}

static void midea_encrypt_to(m_u32 *d, m_u32 *dst, mIDEA_KEY_SCHEDULE *key)
{
    int i;
    register IDEA_INT *p;
    register m_u32 x1,x2,x3,x4,t0,t1,ul;
    
    x2=d[0];
    x1=(x2>>16);
    x4=d[1];
    x3=(x4>>16);
    
    p= &(key->data[0][0]);
    for (i=0; i<8; i++)
	{
	    x1&=0xffff;
	    midea_mul(x1,x1,*p,ul); p++;
	    
	    x2+= *(p++);
	    x3+= *(p++);
	    
	    x4&=0xffff;
	    midea_mul(x4,x4,*p,ul); p++;
	    
	    t0=(x1^x3)&0xffff;
	    midea_mul(t0,t0,*p,ul); p++;
	    
	    t1=(t0+(x2^x4))&0xffff;
	    midea_mul(t1,t1,*p,ul); p++;
	    
	    t0+=t1;
	    
	    x1^=t1;
	    x4^=t0;
	    ul=x2^t0;		/* do the swap to x3 */
	    x2=x3^t1;
	    x3=ul;
	}
    
    x1&=0xffff;
    midea_mul(x1,x1,*p,ul); p++;
    
    t0= x3+ *(p++);
    t1= x2+ *(p++);
    
    x4&=0xffff;
    midea_mul(x4,x4,*p,ul);
    
    dst[0]=(t0&0xffff)|((x1&0xffff)<<16);
    dst[1]=(x4&0xffff)|((t1&0xffff)<<16);
}

static void IDEAencryptCBC(void *opaque, u_char *iv, u_char *data, int len)
{
    int n;
    IDEAcontext *c = opaque;
    mIDEA_KEY_SCHEDULE *ks = &c->enc_ks;
    m_u64 *d = (m_u64*)data;
    if (iv)
	d[0] ^= *(m_u64*)iv;
    midea_encrypt((m_u32*)d, ks);
    len/=8;
    for (n=1; n<len; n++)
	{
	    d[n] ^= d[n-1];
	    midea_encrypt((m_u32*)&d[n], ks);
	}
}

static void IDEAencryptCBCTo(void *opaque, u_char *iv, u_char *data, u_char *dst, int len)
{
    int n;
    IDEAcontext *c = opaque;
    mIDEA_KEY_SCHEDULE *ks = &c->enc_ks;
    m_u64 *d = (m_u64*)data;
    m_u64 *d2 = (m_u64*)dst;
    m_u64 ivb = iv? *(m_u64*)iv: 0;
    len/=8;
    for (n=0; n<len; n++)
	{
	    m_u64 block;
	    block = d[n] ^ ivb;
	    midea_encrypt_to((m_u32*)&block, (m_u32*)&d2[n], ks);
	    ivb = d2[n];
	}
}

static void IDEAdecryptCBC(void *opaque, u_char *iv, u_char *data, int len)
{
    int n;
    IDEAcontext *c = opaque;
    mIDEA_KEY_SCHEDULE *ks = &c->dec_ks;
    m_u64 *d = (m_u64*)data;
    m_u64 ivb = iv? *(m_u64*)iv: 0;
    len/=8;
    for (n=0; n<len; n++)
	{
	    m_u64 ct;
	    ct = d[n];
	    midea_decrypt((m_u32*)&d[n], ks);
	    d[n]^=ivb;
	    ivb = ct;
	}
}

static void IDEAdecryptCBCTo(void *opaque, u_char *iv, u_char *data, u_char *dst, int len)
{
    int n;
    IDEAcontext *c = opaque;
    mIDEA_KEY_SCHEDULE *ks = &c->dec_ks;
    m_u64 *d = (m_u64*)data;
    m_u64 *d2 = (m_u64*)dst;
    midea_decrypt_to((m_u32*)&d[0], (m_u32*)&d2[0], ks);
    if (iv)
	d2[0] ^= *(m_u64*)iv;
    len/=8;
    for (n=1; n<len; n++)
	{
	    midea_decrypt_to((m_u32*)&d[n], (m_u32*)&d2[n], ks);
	    d2[n] ^= d[n-1];
	}
}

EXPORT void IDEAsetkey(void *opaque, u_char *key, int len, int flags)
{
    return
	(flags & MCD_ENCRYPT)?
	    IDEAsetkeyEnc(opaque, key, len)
        :
	    IDEAsetkeyDec(opaque, key, len)
	;
}

EXPORT void IDEAcryptCBC(void *opaque, u_char *iv, u_char *data, u_char *to, int len, int flags)
{
    assert(aligned(len, 8));
    assert(aligned(data, (sizeof(void *))));
    assert(aligned(to, (sizeof(void *))));
    return
	(data == to)?
	       (flags & MCD_ENCRYPT)?
	           IDEAencryptCBC(opaque, iv, data, len)
	       :
	           IDEAdecryptCBC(opaque, iv, data, len)
	   :
               (flags & MCD_ENCRYPT)?
	           IDEAencryptCBCTo(opaque, iv, data, to, len)
	       :
	           IDEAdecryptCBCTo(opaque, iv, data, to, len)
	;
}
