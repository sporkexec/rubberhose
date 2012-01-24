/* $Id: pipeline.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 */
#ifndef PIPELINE_H
#define PIPELINE_H

#include "maru.h"

typedef m_u32 maruPipelineCmd;
typedef m_u32 maruPipelineArg;

typedef struct maruPipeline_st
{
    struct maruPipeline_st *next;
    maruPipelineArg cmd;
    void *arg;
    void *data;
} maruPipeline;

#include "pipeline.ext"

#endif /* PIPELINE_H */
