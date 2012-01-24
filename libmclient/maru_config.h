/* $Id: maru_config.h,v 1.3 2000/05/15 08:35:57 proff Exp $
 * $Copyright:$
 */
#ifndef MARU_CONFIG_H
#define MARU_COFNIG_H

#include "../config.h"

#if 0
/* major number for marutukku devices */
#define MARU_MAJOR		/* 98 */ 7
#endif /* linux */

/* number of aspects, this is randomly modified by hose */
#define MDEF_MARU_ASPECTS 8

#define MDEF_MARU_BLOCK_SIZE 2048

/* default number of blocks, aspect and extent size */
#define MDEF_MARU_BLOCKS 1024

/* max number of marutukku devices */
#define NMARU 			8	

/* max number of hot swap marutukku mirror extents (including primary) */
#define MAX_MIRRORS		4

/* include the xor "cipher" */
#define MC_XOR

/* include the bcopy "cipher" */
#define MC_bcopy

/* include the (patented in some countries) IDEA cipher */
#define MC_IDEA

/* include the CAST cipher */
#define MC_CAST

/* include the Blowfish cipher */
#undef MC_BLOWFISH

#ifdef HAVE_LIBCRYPTO
/* incorporate support for SSLeay ciphers */
#  define MARU_SSLEAY
#endif

#ifdef MARU_SSLEAY
/* include the SSLeay RC2 cipher */
#ifdef HAVE_EVP_RC2_CBC
#  define MC_SSLEAY_RC2
#endif

/* include the SSLeay BLOWFISH cipher */
#ifdef HAVE_EVP_BF_CBC
#  define MC_SSLEAY_BLOWFISH
#endif

/* include the SSLeay RC4 cipher */
#ifdef HAVE_EVP_RC4
#  define MC_SSLEAY_RC4
#endif

/* include the SSLeay IDEA cipher */
#ifdef HAVE_EVP_IDEA_CBC
#  define MC_SSLEAY_IDEA
#endif

/* include the SSLeay DES cipher */
#ifdef HAVE_EVP_DES_CBC
#  define MC_SSLEAY_DES
#endif

/* include the SSLeay DES-EDE (tripple DES) cipher */
#ifdef HAVE_EVP_DES_EDE_CBC
#  define MC_SSLEAY_DES_EDE
#endif

/* include the SSLeay DES-EDE3 (tripple DES with three keys) cipher */
#ifdef HAVE_EVP_DES_EDE3_CBC
#  define MC_SSLEAY_DES_EDE3
#endif

/* include the SSLeay DESX cipher */
#ifdef HAVE_EVP_DESX_CBC
#  define MC_SSLEAY_DESX
#endif

/* include the SSLeay CAST-128 cipher */
#ifdef HAVE_EVP_CAST5_CBC
#  define MC_SSLEAY_CAST
#endif

/* include the SSLeay RC5 cipher */
#ifdef HAVE_EVP_RC5_32_12_16_CBC
#  define MC_SSLEAY_RC5
#endif
#endif /* MARU_SSLEAY */

/* include the RC16 stream cipher */
#define MC_RC16

/* default maru device */
#ifdef linux
#define MDEF_MDEV		"/dev/maru0"
#else
#define MDEF_MDEV 		"/dev/rmaru0"
#endif

#define MDEF_KDEV		"/dev/kue0"

/* default maru extent file name */
#define MDEF_EXT		"maru.extent"

/* default maru keymap file name */
#define MDEF_KEYMAP		"maru.keymap"

/* default Key Cipher */
#define MDEF_KEY_CIPHER		"idea-cbc"

/* default Lattice Cipher */
#define MDEF_LATTICE_CIPHER	"idea-cbc"

/* default Block Cipher */
#define MDEF_BLOCK_CIPHER	"idea-cbc"

/* default socket name for hosed */
#define MDEF_HOSED_SOCKET	"/tmp/maru-test-sock"

#define MDEF_ARGV_MAX		1024

#endif /* MARU_CONFIG_H */
