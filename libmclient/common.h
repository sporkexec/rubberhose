/* $Id: common.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
#ifndef COMMON_H
#define COMMON_H

#ifdef linux
#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/config.h>
#include <linux/string.h>
#include <asm/byteorder.h>
#endif
#endif

#include "common.ext"

#endif
