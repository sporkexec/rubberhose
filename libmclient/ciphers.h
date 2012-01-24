/* $Id: ciphers.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
#ifndef CIPHERS_H
#define CIPHERS_H

#ifdef MC_XOR
#  include "mxor.h"
#endif
#ifdef MC_bcopy
#  include "mbcopy.h"
#endif
#ifdef MC_IDEA
#  include "idea.h"
#endif
#ifdef MC_CAST
#  include "mcast.h"
#endif
#ifdef MC_BLOWFISH
#  include "blowfish.h"
#endif
#ifdef MC_RC4
#  include "rc4"
#endif
#ifdef MC_RC16
#  include "rc16.h"
#endif
#ifdef MARU_SSLEAY
#  include "mSSLeay.h"
#endif
#include "ciphers.ext"

#endif
