/* $Id: maru_types.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
#ifndef MARU_TYPES_H
#define MARU_TYPES_H

#ifdef MARU_MOD
#ifndef linux
#  include <sys/cdefs.h>
#  include <sys/param.h>
#  include <sys/systm.h>
#  include <sys/kernel.h>
#endif
#else
#  include <sys/types.h>
#  ifdef HAVE_SYS_PARAM_H
#    include <sys/param.h>
#  endif
#endif

#include "maru_config.h"

#define bool	int
#define TRUE	1
#define FALSE	0
#define ABORT	-1

typedef
#if	SIZEOF_CHAR	== 1
	char
#elif	SIZEOF_SHORT	== 1
	short 
#elif	SIZEOF_INT	== 1
        int
#elif	SIZEOF_LONG	== 1
	long
#elif	SIZEOF_LONG_INT == 1
        long int
#elif	SIZEOF_LONG_LONG== 1
	long long
#else
#  error no 8 bit type
#endif
		m_8;

typedef unsigned
#if	SIZEOF_CHAR	== 1
	char
#elif	SIZEOF_SHORT	== 1
	short 
#elif	SIZEOF_INT	== 1
        int
#elif	SIZEOF_LONG	== 1
	long
#elif	SIZEOF_LONG_INT == 1
        long int
#elif	SIZEOF_LONG_LONG== 1
	long long
#else
#  error no 8 bit type
#endif
		m_u8;

typedef
#if	SIZEOF_SHORT	== 2
	short
#elif	SIZEOF_INT	== 2
        int
#elif	SIZEOF_LONG	== 2
	long
#elif	SIZEOF_LONG_INT == 2
        long int
#elif	SIZEOF_LONG_LONG== 2
	long long
#else
#  error no 16 bit type
#endif
		m_16;

typedef unsigned
#if	SIZEOF_SHORT	== 2
	short
#elif	SIZEOF_INT	== 2
        int
#elif	SIZEOF_LONG	== 2
	long
#elif	SIZEOF_LONG_INT == 2
        long int
#elif	SIZEOF_LONG_LONG== 2
	long long
#else
#  error no 16 bit type
#endif
		m_u16;

typedef
#if	SIZEOF_SHORT	== 4
	short
#elif	SIZEOF_INT	== 4
        int
#elif	SIZEOF_LONG	== 4
	long
#elif	SIZEOF_LONG_INT == 4
        long int
#elif	SIZEOF_LONG_LONG== 4
	long long
#else
#  error no 32 bit type
#endif
		m_32;
typedef unsigned
#if	SIZEOF_SHORT	== 4
	short
#elif	SIZEOF_INT	== 4
        int
#elif	SIZEOF_LONG	== 4
	long
#elif	SIZEOF_LONG_INT == 4
        long int
#elif	SIZEOF_LONG_LONG== 4
	long long
#else
#  error no 32 bit type
#endif
		m_u32;

typedef
#if	SIZEOF_INT64_T	== 8
	int64_t
#elif	SIZEOF_QUAD_T	== 8
	quad_t
#elif	SIZEOF_INT	== 8
        int
#elif	SIZEOF_LONG	== 8
	long
#elif	SIZEOF_LONG_INT == 8
        long int
#elif	SIZEOF_LONG_LONG== 8
	long long
#else
#  error no 64 bit type
#  define HAVE_BIG64
	m_32
#endif
		m_64;

typedef
#if	SIZEOF_U_INT64_T== 8
	u_int64_t
#elif	SIZEOF_UINT64_T == 8 /* hpux */
	uint64_t
#elif	SIZEOF_U_QUAD_T	== 8
	u_quad_t
#elif	SIZEOF_UQUAD_T	== 8
	uquad_t
#elif	SIZEOF_INT	== 8
        unsigned int
#elif	SIZEOF_LONG	== 8
	unsigned long
#elif	SIZEOF_LONG_INT == 8
        unsigned long int
#elif	SIZEOF_LONG_LONG== 8
	unsigned long long
#else
#  error no unsigned 64 bit type
	m_u32
#endif
		m_u64;

#ifndef MIN
#  define MIN(x,y) (((x)<(y))? (x): (y))
#endif
#ifndef MAX
#  define MAX(x,y) (((x)>(y))? (x): (y))
#endif

#define EITHER(x,y) ((x)? (x): (y))

#ifndef NULL
#  define NULL ((void *)0)
#endif

#define STR(x) #x

#define PACKED __attribute__ ((__packed__))
#define NORETURN __attribute__ ((__noreturn__))

static inline m_u8 hton8(m_u8 x) {return x;}
#define ntoh8 hton8

static inline m_u16 hton16(m_u16 x) {return 
#ifdef WORDS_BIGENDIAN
				       x
#else
				       (m_u16)hton8(x>>8) | ((m_u16)hton8(x) << 8)
#endif
				       ;}
#define ntoh16 hton16

static inline m_u32 hton32(m_u32 x) {return 
#ifdef WORDS_BIGENDIAN
				       x
#else
				       (m_u32)hton16(x>>16) | ((m_u32)hton16(x) << 16)
#endif
				       ;}
#define ntoh32 hton32

static inline m_u64 hton64(m_u64 x) {return 
#ifdef WORDS_BIGENDIAN
				       x
#else
				       (m_u64)hton32(x>>32) | ((m_u64)hton32(x) << 32)
#endif
				       ;}
#define ntoh64 hton64

#define SECURE			struct
#define END_SECURE(label)	*label = maruMalloc(sizeof *label)

#endif /* MARU_TYPES_H */
