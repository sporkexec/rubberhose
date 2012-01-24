/* $Id: psycho.c,v 1.9 2000/05/14 02:37:29 proff Exp $
 * $Copyright:$
 */

#include <err.h>

#include "maru.h"
#include "cipher_tests.h"
#include "client_common.h"

#include "psycho.h"
#include "psycho_unix.h"

#define a(x) if (a_debug>1 || (x) != TRUE) warnx("psychoanalysis: %s... %s", #x, (x)? "passed": (fails++, "failed"))

#define blockAligned(x) ((sizeof(x) % (sizeof(maruBlock))) == 0)

static bool
test_maru_h(int level)
{
    int fails = 0;
    a(MAX_PASSPHRASE >= MIN_PASSPHRASE);
    a(MAX_IV == MAX_CIPHER_BLOCK);
    a(MAX_CIPHER_BLOCK == 8);
    a(sizeof (maruPass) == MAX_PASSPHRASE);
    a(sizeof (maruKey) == MAX_KEY);
    a(sizeof (maruIV) == MAX_IV);
    a(sizeof (maruBlock) == MAX_CIPHER_BLOCK);
    a(blockAligned(maruCycle));
    a(blockAligned(maruAspectInfo));
    return fails;
}

static bool
test_maru_types_h(int level)
{
    int fails = 0;
    a(sizeof (m_u64) == 8);
    a(sizeof (m_u32) == 4);
    a(sizeof (m_u16) == 2);
    a(sizeof (m_u8) == 1);
    a(sizeof (int) >= 4);
#ifdef WORDS_BIGENDIAN
    a(hton8(0x12) == 0x12);
    a(hton16(0x1234) == 0x1234);
    a(hton32(0x12345678) == 0x12345678);
    a(hton64(0x1122334455667788) == 0x1122334455667788);
#else
    a(hton8(0x12) == 0x12);
    a(hton16(0x1234) == 0x3412);
    a(hton32(0x12345678) == 0x78563412);
    a(hton64(0x1122334455667788) == 0x8877665544332211);
#endif
    return fails;
}
#undef a

EXPORT int psychoanalyse(int level)
{
    int result;

    result = test_maru_types_h(level) +
             test_maru_h(level) +
	     psycho_unix(level);
    if (level > 1)
	result += maruCipherTests();
    return result;
}
