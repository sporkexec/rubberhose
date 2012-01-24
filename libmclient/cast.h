/* $Id: cast.h,v 1.1 2000/04/19 16:51:22 proff Exp $
 * $Copyright:$
 */
/*
 *	CAST-128 in C
 *	Written by Steve Reid <sreid@sea-to-sky.net>
 *	100% Public Domain - no warranty
 *	Released 1997.10.11
 */

#ifndef _CAST_H_
#define _CAST_H_

typedef struct {
	m_u32 xkey[32];	/* Key, after expansion */
	int rounds;		/* Number of rounds to use, 12 or 16 */
} cast_key;

void cast_setkey(cast_key* key, m_u8* rawkey, int keybytes);
void cast_encrypt(cast_key* key, m_u8* inblock, m_u8* outblock);
void cast_decrypt(cast_key* key, m_u8* inblock, m_u8* outblock);

#endif /* ifndef _CAST_H_ */

