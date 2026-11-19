#include <lib9.h>
#include <kernel.h>
#include <isa.h>
#include "interp.h"
#include "../libinterp/keyringif.h"
#include "mp.h"
#include "libsec.h"
#include "keys.h"

/*
 * Signature algorithms that sign bytes, not big integers:
 *
 *	ed25519		Ed25519 (RFC 8032)
 *
 * In text, a public key is one line of base64 for each part; a secret
 * key is its public key followed by a 32-byte seed for each part; and
 * a signature is one line for each part. What is signed is Sigprefix,
 * a zero byte, and the digest the certificate names (sha256 for
 * preference).
 */

typedef struct Ekey Ekey;
typedef struct Esig Esig;

enum {
	Seedlen = 32
};

struct Ekey
{
	int	secret;
	uchar	edpub[Ed25519publen];
	uchar	edseed[Seedlen];
};

struct Esig
{
	uchar	ed[Ed25519siglen];
};

static char Sigprefix[] = "inferno signature 1";

static char*	pkattr[] = { "pk", nil };
static char*	skattr[] = { "pk", "!seed", nil };
static char*	sigattr[] = { "val", nil };

/*
 * one line of base64 holding exactly n bytes; the start of the next line, or nil
 */
static char*
getline(char *s, uchar *buf, int n)
{
	char *e;

	if(s == nil)
		return nil;
	e = strchr(s, '\n');
	if(e == nil)
		e = s + strlen(s);
	if(e-s != (n+2)/3*4 || dec64(buf, n, s, e-s) != n)
		return nil;
	if(*e == '\n')
		e++;
	return e;
}

static int
putline(char *buf, int len, uchar *a, int n)
{
	int m;

	if(len < (n+2)/3*4 + 2)
		return 0;
	m = enc64(buf, len-1, a, n);
	if(m < 0)
		return 0;
	buf[m++] = '\n';
	buf[m] = 0;
	return m;
}

static void*
ed_str2sk(char *str, char **strp)
{
	Ekey *k;
	char *p;
	uchar pub[Ed25519publen];

	k = mallocz(sizeof(*k), 1);
	if(k == nil)
		return nil;
	k->secret = 1;
	p = getline(str, k->edpub, sizeof k->edpub);
	p = getline(p, k->edseed, sizeof k->edseed);
	if(p != nil){
		/* the public half must belong to the seed */
		ed25519pub(pub, k->edseed);
		if(memcmp(pub, k->edpub, sizeof pub) != 0)
			p = nil;
	}
	if(p == nil){
		memset(k, 0, sizeof(*k));
		free(k);
		return nil;
	}
	if(strp)
		*strp = p;
	return k;
}

static void*
ed_str2pk(char *str, char **strp)
{
	Ekey *k;
	char *p;

	k = mallocz(sizeof(*k), 1);
	if(k == nil)
		return nil;
	p = getline(str, k->edpub, sizeof k->edpub);
	if(p == nil){
		free(k);
		return nil;
	}
	if(strp)
		*strp = p;
	return k;
}

static void*
ed_str2sig(char *str, char **strp)
{
	Esig *sig;
	char *p;

	sig = mallocz(sizeof(*sig), 1);
	if(sig == nil)
		return nil;
	p = getline(str, sig->ed, sizeof sig->ed);
	if(p == nil){
		free(sig);
		return nil;
	}
	if(strp)
		*strp = p;
	return sig;
}

static int
ed_pk2str(void *vk, char *buf, int len)
{
	Ekey *k;

	k = vk;
	return putline(buf, len, k->edpub, sizeof k->edpub);
}

static int
ed_sk2str(void *vk, char *buf, int len)
{
	Ekey *k;
	int n;

	k = vk;
	n = putline(buf, len, k->edpub, sizeof k->edpub);
	n += putline(buf+n, len-n, k->edseed, sizeof k->edseed);
	return n;
}

static int
ed_sig2str(void *vsig, char *buf, int len)
{
	Esig *sig;

	sig = vsig;
	return putline(buf, len, sig->ed, sizeof sig->ed);
}

static void*
ed_sk2pk(void *vk)
{
	Ekey *k, *pk;

	k = vk;
	pk = mallocz(sizeof(*pk), 1);
	if(pk == nil)
		return nil;
	memmove(pk->edpub, k->edpub, sizeof pk->edpub);
	return pk;
}

static void*
ed_gen(int len)
{
	Ekey *k;

	USED(len);
	k = mallocz(sizeof(*k), 1);
	if(k == nil)
		return nil;
	k->secret = 1;
	genrandom(k->edseed, sizeof k->edseed);
	ed25519pub(k->edpub, k->edseed);
	return k;
}

static void*
ed_genfrompk(void *pk)
{
	USED(pk);
	return ed_gen(0);
}

/* Sigprefix, a zero, the digest */
static int
sigtext(uchar *m, uchar *digest, int n)
{
	if(n < 0 || n > SHA512dlen)
		return -1;
	memmove(m, Sigprefix, sizeof Sigprefix);
	memmove(m+sizeof Sigprefix, digest, n);
	return sizeof Sigprefix + n;
}

static void*
ed_signb(uchar *digest, int n, void *vk)
{
	Ekey *k;
	Esig *sig;
	uchar m[sizeof Sigprefix + SHA512dlen];

	k = vk;
	n = sigtext(m, digest, n);
	if(n < 0 || !k->secret)
		return nil;
	sig = mallocz(sizeof(*sig), 1);
	if(sig == nil)
		return nil;
	ed25519sign(sig->ed, k->edseed, m, n);
	return sig;
}

static int
ed_verifyb(uchar *digest, int n, void *vsig, void *vk)
{
	Ekey *k;
	Esig *sig;
	uchar m[sizeof Sigprefix + SHA512dlen];

	k = vk;
	sig = vsig;
	n = sigtext(m, digest, n);
	if(n < 0)
		return 0;
	return ed25519verify(k->edpub, m, n, sig->ed);
}

/* for signm and verifym, which hand over a big integer */
static void*
ed_sign(mpint *b, void *vk)
{
	uchar buf[SHA512dlen];
	int n;

	if(mpsignif(b) > 8*sizeof buf)
		return nil;
	n = mptobe(b, buf, sizeof buf, nil);
	if(n < 0)
		return nil;
	return ed_signb(buf, n, vk);
}

static int
ed_verify(mpint *b, void *vsig, void *vk)
{
	uchar buf[SHA512dlen];
	int n;

	if(mpsignif(b) > 8*sizeof buf)
		return 0;
	n = mptobe(b, buf, sizeof buf, nil);
	if(n < 0)
		return 0;
	return ed_verifyb(buf, n, vsig, vk);
}

static void
ed_freekey(void *a)
{
	if(a != nil)
		memset(a, 0, sizeof(Ekey));
	free(a);
}

static void
ed_freesig(void *a)
{
	free(a);
}

SigAlgVec*
ed25519init(void)
{
	SigAlgVec *vec;

	vec = mallocz(sizeof(SigAlgVec), 1);
	if(vec == nil)
		return nil;

	vec->name = "ed25519";

	vec->pkattr = pkattr;
	vec->skattr = skattr;
	vec->sigattr = sigattr;

	vec->str2sk = ed_str2sk;
	vec->str2pk = ed_str2pk;
	vec->str2sig = ed_str2sig;

	vec->sk2str = ed_sk2str;
	vec->pk2str = ed_pk2str;
	vec->sig2str = ed_sig2str;

	vec->sk2pk = ed_sk2pk;

	vec->gensk = ed_gen;
	vec->genskfrompk = ed_genfrompk;
	vec->sign = ed_sign;
	vec->verify = ed_verify;
	vec->signb = ed_signb;
	vec->verifyb = ed_verifyb;

	vec->skfree = ed_freekey;
	vec->pkfree = ed_freekey;
	vec->sigfree = ed_freesig;

	return vec;
}
