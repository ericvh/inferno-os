/*
 * Modern primitives for libsec: X25519, Ed25519, XChaCha20-Poly1305
 * (through Monocypher) and HKDF-SHA256. ML-KEM-768 is in mlkem768.c.
 */
#include "os.h"
#include <libsec.h>
#define C99SHIM_HAVE_LIB9
#include "monocypher.h"
#include "monocypher-ed25519.h"

void
x25519(uchar *out, uchar *secret, uchar *point)
{
	crypto_x25519(out, secret, point);
}

void
x25519base(uchar *out, uchar *secret)
{
	crypto_x25519_public_key(out, secret);
}

/* pub is the 32-byte public key of the 32-byte seed */
void
ed25519pub(uchar *pub, uchar *seed)
{
	uchar sk[64], s[32];

	memmove(s, seed, 32);
	crypto_ed25519_key_pair(sk, pub, s);	/* wipes s */
	crypto_wipe(sk, sizeof sk);
}

void
ed25519sign(uchar *sig, uchar *seed, uchar *msg, ulong n)
{
	uchar sk[64], pub[32], s[32];

	memmove(s, seed, 32);
	crypto_ed25519_key_pair(sk, pub, s);
	crypto_ed25519_sign(sig, sk, msg, n);
	crypto_wipe(sk, sizeof sk);
}

/* 1 if sig is pub's signature of msg */
int
ed25519verify(uchar *pub, uchar *msg, ulong n, uchar *sig)
{
	return crypto_ed25519_check(sig, pub, msg, n) == 0;
}

/* out holds n bytes of ciphertext then a 16-byte tag */
void
xchachapolyseal(uchar *out, uchar *key, uchar *nonce, uchar *ad, ulong nad, uchar *plain, ulong n)
{
	crypto_aead_lock(out, out+n, key, nonce, ad, nad, plain, n);
}

/* sealed is n bytes of ciphertext then the tag; 0 if it opens, -1 if not */
int
xchachapolyopen(uchar *out, uchar *key, uchar *nonce, uchar *ad, ulong nad, uchar *sealed, ulong n)
{
	return crypto_aead_unlock(out, sealed+n, key, nonce, ad, nad, sealed, n);
}

static void
hmacsha256(uchar *out, uchar *key, ulong nkey, uchar *a, ulong na, uchar *b, ulong nb, uchar *c, ulong nc)
{
	uchar k[SHA256bsize], pad[SHA256bsize], inner[SHA256dlen];
	DigestState *s;
	int i;

	memset(k, 0, sizeof k);
	if(nkey > SHA256bsize)
		sha256(key, nkey, k, nil);
	else
		memmove(k, key, nkey);
	for(i = 0; i < SHA256bsize; i++)
		pad[i] = k[i] ^ 0x36;
	s = sha256(pad, sizeof pad, nil, nil);
	if(na)
		s = sha256(a, na, nil, s);
	if(nb)
		s = sha256(b, nb, nil, s);
	if(nc)
		s = sha256(c, nc, nil, s);
	sha256(nil, 0, inner, s);
	for(i = 0; i < SHA256bsize; i++)
		pad[i] = k[i] ^ 0x5c;
	s = sha256(pad, sizeof pad, nil, nil);
	sha256(inner, sizeof inner, out, s);
	memset(k, 0, sizeof k);
	memset(pad, 0, sizeof pad);
	memset(inner, 0, sizeof inner);
}

/* RFC 5869; n is at most 255*32. 0 on success, -1 if n is too large */
int
hkdfsha256(uchar *out, ulong n, uchar *salt, ulong nsalt, uchar *ikm, ulong nikm, uchar *info, ulong ninfo)
{
	uchar prk[SHA256dlen], t[SHA256dlen], zero[SHA256dlen], ctr;
	ulong done, m, nt;

	if(n > 255*SHA256dlen)
		return -1;
	if(nsalt == 0){
		memset(zero, 0, sizeof zero);
		salt = zero;
		nsalt = sizeof zero;
	}
	hmacsha256(prk, salt, nsalt, ikm, nikm, nil, 0, nil, 0);
	nt = 0;
	ctr = 1;
	for(done = 0; done < n; done += m){
		hmacsha256(t, prk, sizeof prk, t, nt, info, ninfo, &ctr, 1);
		nt = sizeof t;
		m = n - done;
		if(m > sizeof t)
			m = sizeof t;
		memmove(out+done, t, m);
		ctr++;
	}
	memset(prk, 0, sizeof prk);
	memset(t, 0, sizeof t);
	return 0;
}

/*
 * Work areas for the imported code: see c99shim.h.
 */
void*
secwork(ulong n)
{
	void *p;

	p = mallocz(n, 1);
	if(p == nil)
		sysfatal("secwork: no memory");
	return p;
}

void
secworkfree(void *p, ulong n)
{
	if(p == nil)
		return;
	crypto_wipe(p, n);
	free(p);
}
