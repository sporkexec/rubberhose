/* $Id: mSSLeay.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
#ifndef MSSLEAY_H
#define MSSLEAY_H

#include "mevp.h"

typedef struct
{
    maruCipherDesc *cipher;
    EVP_CIPHER_CTX ctx;
} SSLEAYcontext;

#include "mSSLeay.ext"

#endif
