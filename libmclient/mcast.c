/* $Id: mcast.c,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
#include "maru.h"
#include "maru_types.h"
#include "assert.h"

#include "mcast.h"

EXPORT void CASTinit(maruCipherDesc *cipher, void *opaque, int flags)
{
}

EXPORT void CASTsetkey(void *opaque, u_char *key, int len, int flags)
{
    cast_setkey(opaque, key, len);
}

static void CASTencryptCBC(void *opaque, u_char *iv, u_char *data, int len)
{
    int n;
    m_u64 *d = (m_u64*)data;
    m_u64 iv64;
    if (iv)
	iv64 = *(m_u64*)iv;
    else
        iv64 = 0;
    len/=8;
    for (n=0; n<len; n++)
	{
	    d[n] ^= iv64;
	    cast_encrypt(opaque, (u_char*)&d[n], (u_char*)&d[n]);
	    iv64 = d[n];
	}
}

EXPORT void CASTencryptCBCTo(void *opaque, u_char *iv, u_char *data, u_char *to, int len)
{
    int n;
    m_u64 *d = (m_u64*)data;
    m_u64 *d2 = (m_u64*)to;
    m_u64 iv64 = iv? *(m_u64*)iv: 0;
    len/=8;
    for (n=0; n<len; n++)
	{
	    m_u64 t = d[n] ^ iv64;
	    cast_encrypt(opaque, (u_char*)&t, (u_char*)&d2[n]);
	    iv64 = d2[n];
	}
}

static void CASTdecryptCBC(void *opaque, u_char *iv, u_char *data, int len)
{
    int n;
    m_u64 *d = (m_u64*)data;
    m_u64 iv64;

    if (iv)
        iv64 = *(m_u64*)iv;
    else
        iv64 = 0;
    len/=8;
    for (n=0; n<len; n++)
	{
	    m_u64 t = d[n];
	    cast_decrypt(opaque, (u_char*)&d[n], (u_char*)&d[n]);
	    d[n] ^= iv64;
	    iv64 = t;
	}
}

static void CASTdecryptCBCTo(void *opaque, u_char *iv, u_char *data, u_char *to, int len)
{
    int n;
    m_u64 *d = (m_u64*)data;
    m_u64 *d2 = (m_u64*)to;
    m_u64 iv64;
    if (iv)
        iv64 = *(m_u64*)iv;
    else
        iv64 = 0;
    cast_decrypt(opaque, data, to);
    len/=8;
    for (n=0; n<len; n++)
	{
	    cast_decrypt(opaque, (u_char*)&d[n], (u_char*)&d2[n]);
	    d2[n] ^= iv64;
	    iv64 = d[n];
	}
}

EXPORT void CASTcryptCBC(void *opaque, u_char *iv, u_char *data, u_char *to, int len, int flags)
{
    assert(len % 8 == 0);
    return (data == to)?
	       (flags & MCD_ENCRYPT)?
	           CASTencryptCBC(opaque, iv, data, len)
	       :
	           CASTdecryptCBC(opaque, iv, data, len)
	   :
               (flags & MCD_ENCRYPT)?
	           CASTencryptCBCTo(opaque, iv, data, to, len)
	       :
	           CASTdecryptCBCTo(opaque, iv, data, to, len)
	;
}
	     
