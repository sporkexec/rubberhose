/* $Id: rc16.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
#ifndef RC16_H
#define RC16_H

typedef struct
{
    m_u32 x;
    m_u32 y;
    m_u16 state[65536];
} rc16context;

#include "rc16.ext"

#endif
