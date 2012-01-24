/* $Id: remappers.h,v 1.9 2000/05/15 08:36:19 proff Exp $
 * $Copyright:$
 */

#include "maru.h"
#include "block.h"

#ifndef REMAPPERS_H
#define REMAPPERS_H

typedef m_u32 maruRemapFlags;
enum {RF_DISABLE_REALLOC=1};

typedef struct maruRemapAspectCtx_st
{
    void *data;
} maruRemapAspectCtx;

typedef struct maruRemapInstanceCtx_st
{
    void *data;
} maruRemapInstanceCtx;

typedef enum {I_ASPECT, I_INSTANCE} maruRemapInfoFlag;

typedef struct maruRemapDesc_st
{
    char *name;		/* name */
    char *txt;
    m_u32 (*size)(m_u32 blocks);
    maruKeymapAspectRemap* (*create)(maruInstance *i, m_u32 blocks, int *len, maruRemapFlags remap_flags);
    void* (*new)(maruInstance *i, maruRemapFlags remap_flags);
    void* (*addAspect)(maruAspect *a, maruKeymapAspectRemap *hr);
    bool (*mapIO)(maruReq *req);
    void (*info)(maruInstance *i, int as, maruRemapInfoFlag flag);
    bool (*sync)(maruInstance *i);
    void (*releaseAspect)(maruAspect *a);
    void (*free)(maruInstance *i);
    maruRemapType remapType;
} maruRemapDesc;

#include "remappers.ext"

#endif /* REMAPPERS_H */
