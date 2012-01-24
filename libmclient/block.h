/* $Id: block.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 */
#ifndef BLOCK_H
#define BLOCK_H

typedef enum {MR_READ, MR_WRITE} maruReqOp;

typedef struct
{
    maruAspect *aspect;
    char *data;
    m_u32 block;
    m_u32 blockSize;
    maruReqOp op;
} maruReq;

#include "block.ext"

#endif /* BLOCK_H */
