/* $Id: maru.h,v 1.6 2000/08/16 09:44:06 proff Exp $
 * $Copyright:$
 */

#ifndef MARU_H
#define MARU_H

#include "maru_version.h"
#include "maru_config.h"
#include "maru_types.h"

#ifdef MARU_SSLEAY
#  include "mevp.h"
#endif

/* we make certain assumptions (which we possibly should not) about various
 * data structures being mod 8 = 0 in length. make sure any length definition
 * relfects this assumption
 */

enum {MAX_PASSPHRASE	= 128,
      MIN_PASSPHRASE	= 16,
      MAX_LATTICE_DEPTH	= 32,	/* 2^n blocks addressable with n */
      MAX_KEY		= 32,	/* max key length */  
      MAX_CIPHER_BLOCK	= 8,	/* max cipher block size */
      MAX_MARU_BLOCK    = 8192, /* max maru block size */
      MAX_IV		= 8,	/* max initialisation vector size */
      MAX_PIPELINE      = 16};   /* max commands in maru cipher pipeline */

#define REMAP_USED 0x8000000U
#define SMAP_TYPE m_u32		/* used to encode the split map */

#ifndef MNAMELEN
#  define MNAMELEN 256		/* max sizeof /dev/maru path */
#endif

typedef enum			/* Order is important */
{
    m_none = 0,
    m_CAST_CBC,
    m_IDEA_CBC,
    m_blowfish_CBC,
    m_RC16,
    m_RC4,
    m_SSLEAY_BLOWFISH_CBC,
    m_SSLEAY_DES_CBC,
    m_SSLEAY_DES_EDE_CBC,
    m_SSLEAY_DES_EDE3_CBC,
    m_SSLEAY_DESX_CBC,
    m_SSLEAY_IDEA_CBC,
    m_SSLEAY_RC2_CBC,
    m_SSLEAY_RC4,
    m_SSLEAY_CAST_CBC,
    m_SSLEAY_RC5_CBC,
    m_XOR,
    m_bcopy,
    m_local = 202		/* start of user developed ciphers */
} maruCipher; 			/* nb. we cast this to 8 bits */

enum {MCD_SETKEY_SYMMETRIC	= 1,
      MCD_ENCRYPT 		= 2,
      MCD_DECRYPT		= 4,
      MCD_PARITY		= 8};

typedef struct maruCipherDesc_st
{
#ifdef MARU_SSLEAY
    EVP_CIPHER *(*ssleay)(void);		/* NULL if not a ssleay cipher */
#else
    void *ssleay;
#endif
    void (*init)(struct maruCipherDesc_st *cipher, void *opaque, int flags);
    void (*setkey)(void *opaque, m_u8 *key, int keylen, int flags);
    void (*crypt)(void *opaque, m_u8 *iv, m_u8 *data, m_u8 *to, int len, int flags);
    int (*test)();
    int keylen;
    int blocksize;
    /* XXX to j: this is obsolete... remove comment */
    /* we used to use maruCipherDesc->alloc() and ->free() but this was ugly, requiring the ciphers to
       * know if they were running in kernel space or not and use the kernel malloc routines accordingly
       */
    int opaque_size;	/* internal state size, used by caller to alloc appropriate memory */
    char *txt;		/* one word ascii description */
    m_u32 flags;	/* flags */
    maruCipher cipher;  /* cipher number (enum) */
} maruCipherDesc;

typedef void maruOpaque;

typedef struct
{
    m_u8 data[MAX_PASSPHRASE];
} maruPass;

typedef struct
{
    m_u8 data[MAX_KEY];
} maruKey;

typedef struct
{
    m_u8 data[MAX_IV];
} maruIV;

typedef struct
{
    m_u8 data[MAX_CIPHER_BLOCK];
} maruBlock;

typedef SMAP_TYPE maruSmap;

#define	SMAP_SET(p, n) (((p))[(n)/((sizeof(maruSmap)*8))] |= (1 << ((n) % ((sizeof(maruSmap)*8)))))
#define	SMAP_CLR(p, n) (((p))[(n)/((sizeof(maruSmap)*8))] &= ~ (1 << ((n) % ((sizeof(maruSmap)*8)))))
#define	SMAP_ISSET(p, n) (((p))[(n)/((sizeof(maruSmap)*8))] & (1 << ((n) % ((sizeof(maruSmap)*8)))))

typedef enum {REMAP_NONE=0, REMAP_SPLICE, REMAP_BMAP, REMAP_INVALID} maruRemapType;

typedef struct	/* must be block aligned */
{
    m_u8	pad[4];					/* random padding */
    m_u16 	keySum[2];				/* random, but identical parts */
    maruKey	remapMasterKey;				/* random */
    maruKey	masterKey;				/* random */
    maruKey	infoKey;				/* random */
} maruCycle;

typedef struct	/* must be block aligned */
{
    m_u32	start;
    m_u32	blocks;
    m_u8 	latticeCipherType, blockCipherType;
    m_u8	pad[6];
} maruAspectInfo;

/* the two following structures must appear cryptographically random, whether USED OR NOT.
   Chained functions can defeat some of these properties. For example, if
   pseudo random variables are produced by chaining an initial truly random
   value with a hash cipher, then the stream of values produced can trivially
   be shown to be the output of a hash cipher, simply by comparing pos_n
   with hash(pos_n_-1). see SECURITY for more information */

typedef union
{
    struct maruRemapBmapKeymap_st
    {
	maruKey 	remapKey;		       /* random */
	maruIV 		remapIV;		       /* random */
	m_u32 		remap[2];		       /* encrypted, variable length */
    } bmap;
} maruKeymapAspectRemap;   

typedef struct
{
    maruCycle 		cycle;			       /* encrypted */
    maruCycle		cycleSalt;		       /* random */
    maruAspectInfo	info;			       /* encrypted */
    maruAspectInfo	infoSalt;		       /* random */
    maruKey		passSalt;		       /* random */
    maruKey	 	latticeKeySalt[2];	       /* random */
    maruKey		latticeSalt[2*MAX_LATTICE_DEPTH];	/* random */
    m_u8 		whitener[MAX_MARU_BLOCK];      /* random */
    maruKeymapAspectRemap	remap;			/* random, variable length! */
} maruKeymapAspect;

typedef struct
{
#define MH_MAJ_VERSION 	2
    m_u8 		majVersion; 
#define MH_MIN_VERSION 	1
    m_u8 		minVersion;
    m_u8 		keyCipherType;
    m_u8		remapType;
    m_u32		blocks;
    m_u32		aspectBlocks;		/* max blocks per aspect */
    m_u32 		blockSize;
    m_u32 		depth;
    m_u32 		headSum;		/* keymap checksum */
    m_u32 		iterations;
    m_u32		aspects;
    maruKeymapAspect 	aspect[1];		/* at least one */
} maruKeymap;

/* All the below should probably be moved out of maru.h */

struct maruInstance_s; /* can't forward declare @$@# typedefs */

typedef struct 
{
    struct maruInstance_s *instance; /* back pointer */
    maruCipherDesc        *latticeCipher;
    maruCipherDesc        *blockCipher;
    maruOpaque            *keyOpaque;
    maruOpaque            *latticeOpaque[2];
    maruOpaque            *blockOpaque;
    m_u8                  *whitener;
    m_u8                  *lattice;
    void		  *remapAspectCtx;
    m_u32                  lattice_len;
    m_u32		   start;
    m_u32		   blocks;
    int			   aspect_num;
} maruAspect;

struct maruRemapDesc_st;

typedef struct maruInstance_s                          
{                                                      
    maruAspect 	       **aspect;
    maruCipherDesc 	*keyCipher;                         
    struct maruRemapDesc_st	*remapDesc;
    void		*remapInstanceCtx;
    maruKeymap		*keymap;
    m_u64                extent_size;					/* XXX to be moved into maruExtentInfo */
    m_u64                extent_pos;					/* XXX to be moved into maruExtentInfo */
    m_u32		 aspects;
    m_u32 		 depth;                                       
    m_u32		 blocks;
    m_u32		 aspect_blocks;
    m_u32 		 blockSize;
    m_u32 		 iterations;
    int			 keymap_len;
    int                  extent_fd;					/* XXX to be moved into maruExtentInfo */
    int			 keymap_fd;
} maruInstance;                                        

#endif /* MARU_H *//
