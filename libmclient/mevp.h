/* $Id: mevp.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */

#ifndef MEVP_H
#define MEVP_H

/* SSLeay is a little enthusiastic about including user-space library
 * includes from it's own include files, which would normally prevent
 * Marutukku from using SSLeay ciphers in kernel code.  As a work
 * around, we define our own SSLeay types. Note that EVP_CIPHER and
 * EVP_CIPHER_CTX are meant to be opaque. This would normally be
 * horridly unportable accross different SSLeay versions, but we
 * only reference EVP_CIPHER_CTX->cipher, which is the first structure
 * element or the struct as a whole (opaquely).
 */

#define EVP_RC2_KEY_SIZE	16
#define RC2_BLOCK		8
#define EVP_RC4_KEY_SIZE	16
#define RC2_KEY_LENGTH	16
#define EVP_BLOWFISH_KEY_SIZE	16
#define BF_BLOCK		8
#define EVP_IDEA_KEY_SIZE	16
#define IDEA_BLOCK		8
#define EVP_RC5_KEY_SIZE	16
#define RC5_BLOCK		8
#define EVP_CAST5_KEY_SIZE	16
#define CAST_BLOCK		8

typedef struct evp_cipher_st
{
    int nid;
    int block_size;
    int key_len;
    int iv_len;
    void (*init)();		/* init for encryption */
    void (*do_cipher)();	/* encrypt data */
    void (*cleanup)();		/* used by cipher method */ 
} EVP_CIPHER;

typedef struct evp_cipher_ctx_st
{
    EVP_CIPHER *cipher;
    char dummy[8192-sizeof (void *)];	/* XXX generate automatically */
} EVP_CIPHER_CTX;

EVP_CIPHER *EVP_enc_null(void);		/* nothing :-) */
EVP_CIPHER *EVP_des_ecb(void);
EVP_CIPHER *EVP_des_ede(void);
EVP_CIPHER *EVP_des_ede3(void);
EVP_CIPHER *EVP_des_cfb(void);
EVP_CIPHER *EVP_des_ede_cfb(void);
EVP_CIPHER *EVP_des_ede3_cfb(void);
EVP_CIPHER *EVP_des_ofb(void);
EVP_CIPHER *EVP_des_ede_ofb(void);
EVP_CIPHER *EVP_des_ede3_ofb(void);
EVP_CIPHER *EVP_des_cbc(void);
EVP_CIPHER *EVP_des_ede_cbc(void);
EVP_CIPHER *EVP_des_ede3_cbc(void);
EVP_CIPHER *EVP_desx_cbc(void);
EVP_CIPHER *EVP_rc4(void);
EVP_CIPHER *EVP_idea_ecb(void);
EVP_CIPHER *EVP_idea_cfb(void);
EVP_CIPHER *EVP_idea_ofb(void);
EVP_CIPHER *EVP_idea_cbc(void);
EVP_CIPHER *EVP_rc2_ecb(void);
EVP_CIPHER *EVP_rc2_cbc(void);
EVP_CIPHER *EVP_rc2_cfb(void);
EVP_CIPHER *EVP_rc2_ofb(void);
EVP_CIPHER *EVP_bf_ecb(void);
EVP_CIPHER *EVP_bf_cbc(void);
EVP_CIPHER *EVP_bf_cfb(void);
EVP_CIPHER *EVP_bf_ofb(void);
EVP_CIPHER *EVP_cast5_cbc(void);
EVP_CIPHER *EVP_rc5_32_12_16_cbc(void);


#define	EVP_Cipher(c,o,i,l)	(c)->cipher->do_cipher((c),(o),(i),(l))

void	EVP_CipherInit(EVP_CIPHER_CTX *ctx,EVP_CIPHER *type, unsigned char *key,
		       unsigned char *iv,int enc);
void	EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
			 int *outl, unsigned char *in, int inl);
int	EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

#endif /* MEVP_H */
