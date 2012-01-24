/* $Id: mxor.c,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
#include "maru.h"
#include "assert.h"

#include "mxor.h"

EXPORT void XORinit(maruCipherDesc *cipher, void *opaque, int flags)
{
}

EXPORT void XORsetkey(void *opaque, u_char *key, int len, int flags)
{
}

EXPORT void XORcrypt(void *opaque, u_char *iv, u_char *data, u_char *to, int len, int flags)
{
    int n;
    m_u64 *d = (m_u64*)data;
    m_u64 *d2 = (m_u64*)data;
    assert(aligned(len, 8));
    assert(aligned(data, (sizeof(void *))));
    assert(aligned(to, (sizeof(void *))));
    len/=8;
    for (n=0; n<len; n++)
	d2[n] = d[n]^(m_u64)-1;
}
