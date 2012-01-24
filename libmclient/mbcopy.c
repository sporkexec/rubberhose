/* $Id: mbcopy.c,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */

#include <string.h>

#include "maru.h"
#include "assert.h"

#include "mbcopy.h"

EXPORT void bcopyinit(maruCipherDesc *cipher, void *opaque, int flags)
{
}

EXPORT void bcopysetkey(void *opaque, u_char *key, int len, int flags)
{
}

EXPORT void bcopycrypt(void *opaque, u_char *iv, u_char *data, u_char *to, int len, int flags)
{
    assert(aligned(len, (sizeof(maruBlock))));
    assert(aligned(data, (sizeof (void *))));
    assert(aligned(to, (sizeof(void *))));
    bcopy(data, to, len);
}
