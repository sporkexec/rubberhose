/* $Id: rc16.c,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
/* 
 * rc16 (c) 1997 Julian Assange <proff@iq.org>, All Rights Reserved
 *
 * differences to rc4:
 *
 * produces two bytes at a time (faster), but uses 128k for the internal state
 *
 * 65536! state space (card deck) vs 256!
 *
 */

#include "maru.h"
#include "rc16.h"


EXPORT void rc16init(maruCipherDesc *cipher, void *opaque, int flags)
{
}

EXPORT void rc16setkey(void *opaque, u_char *key, int key_len, int flags)
{
    rc16context *ctx = opaque;
    m_u32 t, u;
    m_u32 keyindex;
    m_u32 stateindex;
    m_u16 *state;
    m_u32 counter;
    
    state = ctx->state;
    ctx->x = 0;
    ctx->y = 0;
    for (counter = 0; counter < 65536; counter++)
      state[counter] = counter;
    keyindex = 0;
    stateindex = 0;
    for (counter = 0; counter < 65536; counter++)
	{
	    t = state[counter];
	    stateindex = (stateindex + key[keyindex] + t) & 0xffff;
	    u = state[stateindex];
	    state[stateindex] = t;
	    state[counter] = u;
	    if (++keyindex >= key_len)
		keyindex = 0;
	}
}

static inline m_u16 rc16_short(void *opaque)
{
    rc16context *ctx = opaque;
    m_u32 x;
    m_u32 y;
    m_u32 sx, sy;
    m_u16 *state;
    
    state = ctx->state;
    x = (ctx->x + 1) & 0xffff;
    sx = state[x];
    y = (sx + ctx->y) & 0xffff;
    sy = state[y];
    ctx->x = x;
    ctx->y = y;
    state[y] = sx;
    state[x] = sy;
    return state[(sx + sy) & 0xffff];
}

static void rc16encrypt(void *opaque, u_char *iv, u_char *data, int len)
{
    rc16context *ctx = opaque;
    int n;
    m_u16 *p = (m_u16 *)data;
    int odd = len&1;
    len/=2;
    for (n=0; n<len; n++)
	p[n]^=rc16_short(ctx);
    if (odd)
	    data[n*2] ^= rc16_short(ctx)&0xff;
}

static void rc16encryptTo(void *opaque, u_char *iv, u_char *data, u_char *to, int len)
{
    rc16context *ctx = opaque;
    int n;
    m_u16 *p = (m_u16 *)data;
    m_u16 *p2 = (m_u16 *)to;
    int odd = len&1;
    len/=2;
    for (n=0; n<len; n++)
	p2[n]=p[n]^rc16_short(ctx);
    if (odd)
	to[n*2] = data[n*2]^(rc16_short(ctx)&0xff);
}

EXPORT void rc16crypt(void *opaque, u_char *iv, u_char *data, u_char *to, int len, int flags)
{
    return
	(to == data)?
	    rc16encrypt(opaque, iv, data, len)
        :
	    rc16encryptTo(opaque, iv, data, to, len)
        ;
}

EXPORT void rc16stir(void *opaque, int n)
{
    rc16context *ctx = opaque;
    for (;n>0; n--)
	{
	    m_u32 sx, sy, x, y;
	    m_u16 *state;
	    
	    state = ctx->state;
	    x = (ctx->x + 1) & 0xffff;
	    sx = state[x];
	    y = (sx + ctx->y) & 0xffff;
	    sy = state[y];
	    ctx->x = x;
	    ctx->y = y;
	    state[y] = sx;
	    state[x] = sy;
	}
}
