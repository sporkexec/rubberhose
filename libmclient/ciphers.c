/* $Id: ciphers.c,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
#include "maru.h"
#include "ciphers.h"

EXPORT maruCipherDesc m_ciphers[] =
{
#ifdef MC_XOR
    {NULL,			/* SSLEAY cipher pointer */
     XORinit,			/* initialise cipher */
     XORsetkey,			/* setkey */
     XORcrypt,			/* crypt */
#warning MC_XOR test vector function not defined
     NULL,			/* test */
     0, 			/* keylen */
     0,				/* blocksize */
     sizeof(int),		/* internal state size */
     "xor",			/* one word ascii description */
     MCD_SETKEY_SYMMETRIC,	/* flags */
     m_XOR			/* cipherType */
    },
#endif
#ifdef MC_bcopy
    {NULL,			/* SSLEAY cipher pointer */
     bcopyinit,			/* initialise cipher */
     bcopysetkey,		/* setkey */
     bcopycrypt,		/* crypt */
#warning MC_bcopy test vector function not defined
     NULL,			/* test */
     0, 			/* keylen */
     0,				/* blocksize */
     sizeof(int),		/* internal state size */
     "bcopy",			/* one word ascii description */
     MCD_SETKEY_SYMMETRIC,	/* flags */
     m_bcopy			/* cipherType */
    },
#endif
#ifdef MC_IDEA
    {NULL,
     IDEAinit,			/* initialise cipher */
     IDEAsetkey,		/* setkey */
     IDEAcryptCBC,		/* crypt  */
#warning MC_IDEA test vector function not defined
     NULL,			/* test */
     16, 			/* keylen */
     8,				/* blocksize */
     sizeof(IDEAcontext),	/* internal state size */
     "idea-cbc",		/* one word ascii description */
     0,				/* flags */
     m_IDEA_CBC			/* cipherType */
    },
#endif
#ifdef MC_CAST
    {NULL,			/* SSLEAY cipher pointer */
     CASTinit,			/* initialise cipher */
     CASTsetkey,		/* setkey */
     CASTcryptCBC,		/* crypt */
#warning MC_CAST test vector function not defined
     NULL,			/* test */
     16, 			/* keylen */
     8,				/* blocksize */
     sizeof(CASTcontext),	/* internal state size */
     "cast-cbc",		/* one word ascii description */
     MCD_SETKEY_SYMMETRIC,	/* flags */
     m_CAST_CBC			/* cipherType */
    },
#endif
#ifdef MC_BLOWFISH
    {NULL,			/* SSLEAY cipher pointer */
     blowfishinit,		/* initialise cipher */
     blowfishsetkey,		/* setkey */
     blowfishcryptCBC,		/* encrypt */
#warning MC_BLOWFISH test vector function not defined
     NULL,			/* test */
     BLF_MAXKEYLEN, 		/* keylen */
     8,				/* blocksize */
     sizeof(blf_ctx),		/* internal state size */
     "blowfish-cbc",		/* one word ascii description */
     MCD_SETKEY_SYMMETRIC,	/* flags */
     m_blowfish_CBC		/* cipherType */
    },
#endif
#ifdef MC_SSLEAY_BLOWFISH
    {EVP_bf_cbc,		/* SSLEAY cipher pointer */
     SSLEAYinit,		/* initialise cipher */
     SSLEAYsetkey,		/* setkey */
     SSLEAYcrypt,		/* crypt */
#warning MC_SSLEAY_BLOWFISH test vector function not defined
     NULL,			/* test */
     56,		 	/* keylen */
     BF_BLOCK,			/* blocksize */
     sizeof(SSLEAYcontext),	/* internal state size */
     "ssl-blowfish-cbc",	/* one word ascii description */
     MCD_SETKEY_SYMMETRIC,	/* flags */
     m_SSLEAY_BLOWFISH_CBC	/* cipherType */
    },
#endif
#ifdef MC_SSLEAY_RC2
    {EVP_rc2_cbc,		/* SSLEAY cipher pointer */
     SSLEAYinit,		/* initialise cipher */
     SSLEAYsetkey,		/* setkey */
     SSLEAYcrypt,		/* crypt */
#warning MC_SSLEAY_RC2 test vector function not defined
     NULL,			/* test */
     EVP_RC2_KEY_SIZE, 		/* keylen */
     RC2_BLOCK,			/* blocksize */
     sizeof(SSLEAYcontext),	/* internal state size */
     "ssl-rc2-cbc",		/* one word ascii description */
     MCD_SETKEY_SYMMETRIC,	/* flags */
     m_SSLEAY_RC2_CBC		/* cipherType */
    },
#endif
#ifdef MC_SSLEAY_RC4
    {EVP_rc4,			/* SSLEAY cipher pointer */
     SSLEAYinit,		/* initialise cipher */
     SSLEAYsetkey,		/* setkey */
     SSLEAYcrypt,		/* crypt */
#warning MC_SSLEAY_RC4 test vector function not defined
     NULL,			/* test */
     0, 			/* keylen */
     0,				/* blocksize */
     sizeof(SSLEAYcontext),	/* internal state size */
     "ssl-rc4",			/* one word ascii description */
     MCD_SETKEY_SYMMETRIC,	/* flags */
     m_SSLEAY_RC4		/* cipherType */
    },
#endif
#ifdef MC_SSLEAY_RC5
    {EVP_rc5_32_12_16_cbc,	/* SSLEAY cipher pointer */
     SSLEAYinit,		/* initialise cipher */
     SSLEAYsetkey,		/* setkey */
     SSLEAYcrypt,		/* crypt */
#warning MC_SSLEAY_RC5 test vector function not defined
     NULL,			/* test */
     EVP_RC5_KEY_SIZE, 		/* keylen */
     RC5_BLOCK,			/* blocksize */
     sizeof(SSLEAYcontext),	/* internal state size */
     "ssl-rc5-cbc",		/* one word ascii description */
     0,				/* flags */
     m_SSLEAY_RC5_CBC		/* cipherType */
    },
#endif
#ifdef MC_SSLEAY_IDEA
    {EVP_idea_cbc,		/* SSLEAY cipher pointer */
     SSLEAYinit,		/* initialise cipher */
     SSLEAYsetkey,		/* setkey */
     SSLEAYcrypt,		/* crypt */
#warning MC_SSLEAY_IDEA test vector function not defined
     NULL,			/* test */
     EVP_IDEA_KEY_SIZE, 	/* keylen */
     IDEA_BLOCK,		/* blocksize */
     sizeof(SSLEAYcontext),	/* internal state size */
     "ssl-idea-cbc",		/* one word ascii description */
     0,				/* flags */
     m_SSLEAY_IDEA_CBC		/* cipherType */
    },
#endif
#ifdef MC_SSLEAY_DES
    {EVP_des_cbc,		/* SSLEAY cipher pointer */
     SSLEAYinit,		/* initialise cipher */
     SSLEAYsetkey,		/* setkey */
     SSLEAYcrypt,		/* crypt */
#warning MC_SSLEAY_DES test vector function not defined
     NULL,			/* test */
     8,				/* keylen */
     8,				/* blocksize */
     sizeof(SSLEAYcontext),	/* internal state size */
     "ssl-des-cbc",		/* one word ascii description */
     MCD_SETKEY_SYMMETRIC|MCD_PARITY,	/* flags */
     m_SSLEAY_DES_CBC		/* cipherType */
    },
#endif
#ifdef MC_SSLEAY_DES_EDE
    {EVP_des_ede_cbc,		/* SSLEAY cipher pointer */
     SSLEAYinit,		/* initialise cipher */
     SSLEAYsetkey,		/* setkey */
     SSLEAYcrypt,		/* crypt */
#warning MC_SSLEAY_DES_EDE test vector function not defined
     NULL,			/* test */
     16,			/* keylen */
     8,				/* blocksize */
     sizeof(SSLEAYcontext),	/* internal state size */
     "ssl-des-ede-cbc",		/* one word ascii description */
     MCD_SETKEY_SYMMETRIC|MCD_PARITY,	/* flags */
     m_SSLEAY_DES_EDE_CBC	/* cipherType */
    },
#endif
#ifdef MC_SSLEAY_DES_EDE3
    {EVP_des_ede3_cbc,		/* SSLEAY cipher pointer */
     SSLEAYinit,		/* initialise cipher */
     SSLEAYsetkey,		/* setkey */
     SSLEAYcrypt,		/* crypt */
#warning MC_SSLEAY_DES_EDE3 test vector function not defined
     NULL,			/* test */
     24,			/* keylen */
     8,				/* blocksize */
     sizeof(SSLEAYcontext),	/* internal state size */
     "ssl-des-ede3-cbc",	/* one word ascii description */
     MCD_SETKEY_SYMMETRIC|MCD_PARITY,	/* flags */
     m_SSLEAY_DES_EDE3_CBC	/* cipherType */
    },
#endif
#ifdef MC_SSLEAY_DESX
    {EVP_desx_cbc,		/* SSLEAY cipher pointer */
     SSLEAYinit,		/* initialise cipher */
     SSLEAYsetkey,		/* setkey */
     SSLEAYcrypt,		/* crypt */
#warning MC_SSLEAY_DESX test vector function not defined
     NULL,			/* test */
     24,			/* keylen */
     8,				/* blocksize */
     sizeof(SSLEAYcontext),	/* internal state size */
     "ssl-desx-cbc",		/* one word ascii description */
     MCD_SETKEY_SYMMETRIC|MCD_PARITY,	/* flags */
     m_SSLEAY_DESX_CBC		/* cipherType */
    },
#endif
#ifdef MC_SSLEAY_CAST
    {EVP_cast5_cbc,		/* SSLEAY cipher pointer */
     SSLEAYinit,		/* initialise cipher */
     SSLEAYsetkey,		/* setkey */
     SSLEAYcrypt,		/* crypt */
#warning MC_SSLEAY_CAST test vector function not defined
     NULL,			/* test */
     EVP_CAST5_KEY_SIZE,	/* keylen */
     CAST_BLOCK,		/* blocksize */
     sizeof(SSLEAYcontext),	/* internal state size */
     "ssl-cast-cbc",		/* one word ascii description */
     MCD_SETKEY_SYMMETRIC,	/* flags */
     m_SSLEAY_CAST_CBC		/* cipherType */
    },
#endif
#ifdef MC_RC4
    {NULL,			/* SSLEAY cipher pointer */
     rc4init,			/* initialise cipher */
     rc4setkey */
     rc4crypt,			/* crypt */
#warning MC_RC4 test vector function not defined
     NULL,			/* test */
     0,	 			/* keylen */
     0,				/* blocksize */
     0,				/* internal state size */
     "rc4",			/* one word ascii description */
     MCD_SETKEY_SYMMETRIC,	/* flags */
     m_RC4			/* cipherType */
    },
#endif /* MC_RC4 */
#ifdef MC_RC16
    {NULL,			/* SSLEAY cipher pointer */
     rc16init,			/* initialise cipher */
     rc16setkey,		/* setkey */
     rc16crypt,			/* crypt */
#warning MC_RC16 test vector function not defined
     NULL,			/* test */
     0,	 			/* keylen */
     0,				/* blocksize */
     sizeof(rc16context),	/* internal state size */
     "rc16",			/* one word ascii description */
     MCD_SETKEY_SYMMETRIC,	/* flags */
     m_RC16,			/* cipherType */
    },
#endif /* MC_RC16 */
    { /* NULL terminator */
    }
};
