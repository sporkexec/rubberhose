#include <err.h>

#include "maru.h"
#include "ciphers.h"
#include "common.h"
#include "client_common.h"

#include "cipher_tests.h"

static void run_cipher(maruCipherDesc *c, maruKey *key, maruIV *IV, char *b0, char *b1, int len, int ply)
{
    int n;
    maruOpaque *ctx = maruOpaqueInit(c);
    c->setkey(ctx, key->data, EITHER(c->keylen, sizeof key), MCD_ENCRYPT);
    for (n=0; n<ply; n++)
	{
	    c->crypt(ctx, IV->data, b0, b1, len, MCD_ENCRYPT);
	    c->crypt(ctx, IV->data, b1, b0, len, MCD_ENCRYPT);
	}
    c->setkey(ctx, key->data, EITHER(c->keylen, sizeof key), MCD_DECRYPT);
    for (n=0; n<ply; n++)
	{
	    c->crypt(ctx, IV->data, b0, b1, len, MCD_DECRYPT);
	    c->crypt(ctx, IV->data, b1, b0, len, MCD_DECRYPT);
	}
    maruOpaqueFree(ctx);
}

EXPORT int maruCipherTests()
{
    maruCipherDesc *c;
    m_u8 buf[256], buf2[sizeof buf];
    maruKey key;
    maruKey key2;
    maruIV IV;
    int failures = 0;
    int ply = 1;
    maruRandom(&key, sizeof key, RAND_PSEUDO, NULL);
    memcpy(&key2, &key, sizeof key);
    maruRandom(&IV, sizeof IV, RAND_PSEUDO, NULL);
    maruRandom(buf2, sizeof buf2, RAND_PSEUDO, NULL);
    for (c = m_ciphers; c->cipher != m_none; c++)
	{
	    if (c->test)
		{
		    int n = c->test();
		    if (n>0)
			{
			    warnx("psychoanalysis: %s %d internal test vector%s... failed", c->txt, n, (n==1)? "": "s");
			    failures += n;
			}
		    else
			if (a_debug>1)
			    warnx("psychoanalysis: %s internal test vectors... passed", c->txt);
		}
	    {
		m_u8 buf3[sizeof buf];
		memcpy(buf, buf2, sizeof buf);
		run_cipher(c, &key, &IV, buf, buf, sizeof buf, ply);
		if (memcmp(buf, buf2, sizeof buf) != 0)
		    {
		        warnx("psychoanalysis: %s auto test vector in == out, ply = %d... failed", c->txt, ply);
			failures++;
		    }
		else
		    if (a_debug>1)
			warnx("psychoanalysis: %s auto test vector in == out, ply = %d... passed", c->txt, ply);
		memcpy(buf, buf2, sizeof buf);
		run_cipher(c, &key, &IV, buf, buf3, sizeof buf, ply);
		if (memcmp(buf, buf2, sizeof buf) != 0)
		    {
		        warnx("psychoanalysis: %s auto test vector in != out, ply = %d... failed", c->txt, ply);
			failures++;
		    }
		else
		    if (a_debug>1)
			warnx("psychoanalysis: %s auto test vector in != out, ply = %d... passed", c->txt, ply);
	    }
	}
    return failures;
}
