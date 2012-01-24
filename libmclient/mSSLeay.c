/* $Id: mSSLeay.c,v 1.2 2000/05/12 06:45:52 proff Exp $
 * $Copyright:$
 */
#include <strings.h>

#include "maru.h"
#include "assert.h"

#include "mSSLeay.h"

EXPORT void SSLEAYinit(maruCipherDesc *cipher, void *opaque, int flags)
{
    SSLEAYcontext *ctx = opaque;
    assert(cipher);
    ctx->cipher = cipher;
    ctx->ctx.cipher = cipher->ssleay();
}

EXPORT void SSLEAYsetkey(void *opaque, u_char *key, int len, int flags)
{
    u_char buf[MAX_KEY];
    SSLEAYcontext *ctx = opaque;
    assert(ctx);
    if (len < ctx->cipher->keylen)
	{
	    int blen = MIN(len, sizeof buf);
	    bzero(buf, MIN(ctx->cipher->keylen, sizeof buf));
	    memcpy(buf, key, blen);
	    EVP_CipherInit(&ctx->ctx, NULL, buf, NULL, (flags & MCD_ENCRYPT)!=0);
	    bzero(buf, blen); /* too quick to worry about memory cell oxide build up */
	}
    else
	{
	    EVP_CipherInit(&ctx->ctx, NULL, key, NULL, (flags & MCD_ENCRYPT)!=0);
	}
}

EXPORT void SSLEAYcrypt(void *opaque, u_char *iv, u_char *data, u_char *to, int len, int flags)
{
    SSLEAYcontext *ctx = opaque;
    assert(ctx);
    assert(ctx->cipher->blocksize == 0 || len%ctx->cipher->blocksize == 0);
    if (iv)
	EVP_CipherInit(&ctx->ctx, NULL, NULL, iv, (flags & MCD_ENCRYPT)!=0);
    else
	{
	    m_u64 iv = 0; /* XXX presumptuous size */
	    /* SSLeay lossage: there is no way to tell EVP_CipherInit
	       * to *stop* using an iv -- NULL in the iv field means.
	       * "don't change". we hack around this by using an
	       * all 0 iv */
	    EVP_CipherInit(&ctx->ctx, NULL, NULL, (u_char*)&iv, (flags & MCD_ENCRYPT)!=0);
	} 

#ifdef SSLeay_IS_LAME
    /* SSLeay lossage: from must not equal to for block ciphers */
    if (data == to && ctx->cipher->blocksize >0)
	{
	    u_char buf[len+ctx->cipher->blocksize]; /* XXX ANSI violation */
	    EVP_Cipher(&ctx->ctx, buf, data, len);  /* XXX undocumented API */
	    memcpy(data, buf, len);
	}
    else
#endif
	{
	    EVP_Cipher(&ctx->ctx, to, data, len);
	}
}

EXPORT void SSLEAYstir(void *opaque, int rounds)
{
    u_char junk[256];
    while (rounds>0)
	{
	    int cc = MIN(sizeof junk, rounds);
	    SSLEAYcrypt(opaque, NULL, junk, junk, cc, MCD_ENCRYPT);
	    rounds-=cc;
	}
    bzero(junk, sizeof junk);
}
