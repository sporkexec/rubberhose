/* $Id: kue-api.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */

#ifndef KUE_API_H
#define KUE_API_H

#ifndef linux
#include "kue_bsd_ioctl.h"
#endif

#define KUE_ALIGNMENT sizeof(void *)
#define KUE_WORDALIGN(x) (((x)+(KUE_ALIGNMENT-1))&~(KUE_ALIGNMENT-1))
#define KUE_HLEN		KUE_WORDALIGN(sizeof (struct kue_message))

struct kue_message
{
    m_u32 km_len;
};

#endif /* KUE_API_H */
