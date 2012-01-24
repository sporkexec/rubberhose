/* $Id: client_common.h,v 1.8 2000/05/14 02:37:55 proff Exp $
 * $Copyright:$
 */
#ifndef CLIENT_COMMON_H
#define CLIENT_COMMON_H

#ifndef _PATH_RANDOM
#  define _PATH_RANDOM "/dev/random"
#endif
#ifndef _PATH_URANDOM
#  define _PATH_URANDOM "/dev/urandom"
#endif

typedef enum {RAND_PSEUDO, RAND_TRUE} maru_random;

#include <stdio.h>

#include "maru.h"
#include "remappers.h"

#include "client_common.ext"

#endif
