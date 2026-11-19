implement Lethefs;

#
# lethefs [-A] [-D] [-C x25519] [-k seedfile] [-u user] addr mtpt
#
# A Lethe client (docs/lethe.md in Purgatorio, protocol lethe1): dials a
# lethed, and presents its read-only tree at mtpt by serving Styx on a pipe.
# The server keeps no state; the fid table Styx needs lives here.
#
# With -A it uses the clear mode (Tclear/Rclear). Otherwise it authenticates
# with the Ed25519 key whose 32-byte seed is in seedfile, gets a ticket from
# the hybrid X25519 + ML-KEM-768 exchange (Tauth2), and seals every request
# with XChaCha20-Poly1305. -C x25519 asks for the classical exchange (Tauth).
# Neither mode falls back to the other.
#

include "sys.m";
	sys: Sys;
	Qid, Dir: import Sys;
include "draw.m";
include "arg.m";
include "dial.m";
	dial: Dial;
include "styx.m";
	styx: Styx;
	Tmsg, Rmsg: import styx;
include "ipints.m";
include "crypt.m";
	crypt: Crypt;
include "keyring.m";
include "security.m";
	random: Random;
include "daytime.m";
	daytime: Daytime;

Lethefs: module
{
	init: fn(nil: ref Draw->Context, args: list of string);
};

# outer frame types
Tauth:	con 1;
Rauth:	con 2;
Treq:	con 3;
Rreq:	con 4;
Rerror:	con 5;
Tclear:	con 9;
Rclear:	con 10;
Tauth2:	con 11;
Rauth2:	con 12;

Rread:	con 1;	# rights
Noncelen:	con 24;
Taglen:	con 16;

# inner ops
OTstat:	con 16r10;
ORstat:	con 16r11;
OTread:	con 16r12;
ORread:	con 16r13;
OTreaddir:	con 16r14;
ORreaddir:	con 16r15;
OTwalk:	con 16r18;
ORwalk:	con 16r19;
ORerror:	con 16r7f;

Maxframe:	con 65536;
Maxread:	con 32768;
Maxwalk:	con 64;

Eperm:	con "permission denied";
Ebadfid:	con "unknown fid";
Einuse:	con "fid in use";
Enotdir:	con "not a directory";
Eisdir:	con "file is a directory";
Eopen:	con "fid is open";
Enotopen:	con "fid is not open";
Ebadmsg:	con "bad lethe message";

Fid: adt {
	fid:	int;
	path:	string;
	qid:	Qid;
	open:	int;
	dirbuf:	array of byte;	# a directory's entries, read whole at offset 0
};

fids: list of ref Fid;
lfd: ref Sys->FD;	# the connection to lethed
lid := 0;

# the sealed mode's state: what an exchange gave
clear := 0;
classical := 0;	# -C x25519: ask for Tauth, not Tauth2
seed: array of byte;	# the user's Ed25519 seed
uname: string;
ticket: array of byte;
c2s, s2c: array of byte;
skew := 0;	# the server's clock less ours, in seconds
debug := 0;
stderr: ref Sys->FD;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	stderr = sys->fildes(2);
	styx = load Styx Styx->PATH;
	dial = load Dial Dial->PATH;
	arg := load Arg Arg->PATH;
	if(styx == nil || dial == nil || arg == nil)
		fatal("cannot load modules");
	styx->init();

	keyfile: string;
	arg->init(args);
	arg->setusage("lethefs [-A] [-D] [-C x25519] [-k seedfile] [-u user] addr mtpt");
	while((o := arg->opt()) != 0)
		case o {
		'A' =>	clear = 1;
		'D' =>	debug = 1;
		'k' =>	keyfile = arg->earg();
		'u' =>	uname = arg->earg();
		'C' =>
			case arg->earg() {
			"x25519" =>	classical = 1;
			"x25519mlkem768" =>	classical = 0;
			* =>	fatal("unknown key exchange");
			}
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 2)
		arg->usage();
	if(!clear){
		if(keyfile == nil)
			fatal("no key: give -k seedfile, or -A for the clear mode");
		crypt = load Crypt Crypt->PATH;
		random = load Random Random->PATH;
		daytime = load Daytime Daytime->PATH;
		if(crypt == nil || random == nil || daytime == nil)
			fatal("cannot load crypto modules");
		seed = readseed(keyfile);
		if(uname == nil)
			uname = readfile("/dev/user");
	}
	addr := dial->netmkaddr(hd args, "tcp", "5640");
	mtpt := hd tl args;

	c := dial->dial(addr, nil);
	if(c == nil)
		fatal(sys->sprint("dial %s: %r", addr));
	lfd = c.dfd;

	if(!clear){
		e := authenticate();
		if(e != nil)
			fatal(e);
	}
	# fail now, not at the first walk, if the server refuses us
	(nil, err) := lstat("/");
	if(err != nil)
		fatal(err);

	fds := array[2] of ref Sys->FD;
	if(sys->pipe(fds) < 0)
		fatal(sys->sprint("pipe: %r"));
	spawn serve(fds[0]);
	if(sys->mount(fds[1], nil, mtpt, Sys->MREPL, nil) < 0)
		fatal(sys->sprint("mount %s: %r", mtpt));
}

fatal(s: string)
{
	sys->fprint(stderr, "lethefs: %s\n", s);
	raise "fail:error";
}

#
# The Styx side.
#

serve(fd: ref Sys->FD)
{
	sys->pctl(Sys->NEWFD, fd.fd :: lfd.fd :: 2 :: nil);
	fd = sys->fildes(fd.fd);
	lfd = sys->fildes(lfd.fd);
	stderr = sys->fildes(2);
	msize := Styx->MAXRPC;
	for(;;){
		t := Tmsg.read(fd, msize);
		if(t == nil)
			break;
		r: ref Rmsg;
		pick m := t {
		Readerror =>
			sys->fprint(stderr, "lethefs: styx read: %s\n", m.error);
			return;
		Version =>
			(ms, v) := styx->compatible(m, Maxread+Styx->IOHDRSZ, Styx->VERSION);
			msize = ms;
			r = ref Rmsg.Version(m.tag, ms, v);
		Auth =>
			r = rerror(m.tag, "authentication not required");
		Attach =>
			r = attach(m);
		Flush =>
			r = ref Rmsg.Flush(m.tag);
		Walk =>
			r = walk(m);
		Open =>
			r = open(m);
		Read =>
			r = read(m);
		Stat =>
			r = stat(m);
		Clunk =>
			delfid(m.fid);
			r = ref Rmsg.Clunk(m.tag);
		* =>
			# create, write, remove, wstat: the tree is read-only
			r = rerror(t.tag, Eperm);
		}
		if(debug)
			sys->fprint(stderr, "%s\n-> %s\n", t.text(), r.text());
		a := r.pack();
		if(sys->write(fd, a, len a) != len a)
			break;
	}
}

rerror(tag: int, e: string): ref Rmsg
{
	return ref Rmsg.Error(tag, e);
}

getfid(n: int): ref Fid
{
	for(l := fids; l != nil; l = tl l)
		if((hd l).fid == n)
			return hd l;
	return nil;
}

delfid(n: int)
{
	nl: list of ref Fid;
	for(l := fids; l != nil; l = tl l)
		if((hd l).fid != n)
			nl = hd l :: nl;
	fids = nl;
}

attach(m: ref Tmsg.Attach): ref Rmsg
{
	if(getfid(m.fid) != nil)
		return rerror(m.tag, Einuse);
	(d, err) := lstat("/");
	if(err != nil)
		return rerror(m.tag, err);
	fids = ref Fid(m.fid, "/", d.qid, 0, nil) :: fids;
	return ref Rmsg.Attach(m.tag, d.qid);
}

join(path, name: string): string
{
	if(path == "/")
		return "/" + name;
	return path + "/" + name;
}

parent(path: string): string
{
	for(i := len path - 1; i > 0; i--)
		if(path[i] == '/')
			return path[0:i];
	return "/";
}

walk(m: ref Tmsg.Walk): ref Rmsg
{
	f := getfid(m.fid);
	if(f == nil)
		return rerror(m.tag, Ebadfid);
	if(f.open)
		return rerror(m.tag, Eopen);
	if(m.newfid != m.fid && getfid(m.newfid) != nil)
		return rerror(m.tag, Einuse);
	n := len m.names;
	path := f.path;
	qid := f.qid;
	qids := array[n] of Qid;
	nq := 0;
	err: string;
	i := 0;
	while(i < n && err == nil){
		if(m.names[i] == ".."){
			# names are lexical: resolve .. here and ask for the result
			path = parent(path);
			d: ref Dir;
			(d, err) = lstat(path);
			if(err != nil)
				break;
			qid = d.qid;
			qids[nq++] = qid;
			i++;
			continue;
		}
		# one Twalk for the run of names up to the next ..
		j := i;
		while(j < n && m.names[j] != ".." && j-i < Maxwalk)
			j++;
		wq: array of Qid;
		(wq, err) = lwalk(path, m.names[i:j]);
		for(k := 0; k < len wq; k++){
			path = join(path, m.names[i+k]);
			qid = wq[k];
			qids[nq++] = qid;
		}
		i = j;
	}
	if(nq < n){
		# as 9P: an error only if the first name failed
		if(nq == 0)
			return rerror(m.tag, err);
		return ref Rmsg.Walk(m.tag, qids[0:nq]);
	}
	if(m.newfid == m.fid){
		f.path = path;
		f.qid = qid;
	}else
		fids = ref Fid(m.newfid, path, qid, 0, nil) :: fids;
	return ref Rmsg.Walk(m.tag, qids);
}

open(m: ref Tmsg.Open): ref Rmsg
{
	f := getfid(m.fid);
	if(f == nil)
		return rerror(m.tag, Ebadfid);
	if(f.open)
		return rerror(m.tag, Eopen);
	if((m.mode & 3) != Styx->OREAD && (m.mode & 3) != Styx->OEXEC || (m.mode & (Styx->OTRUNC|Styx->ORCLOSE)) != 0)
		return rerror(m.tag, Eperm);
	# the server checks permission on each request; ask once here so that
	# an open of an unreadable file fails as an open
	(d, err) := lstat(f.path);
	if(err != nil)
		return rerror(m.tag, err);
	f.qid = d.qid;
	f.open = 1;
	return ref Rmsg.Open(m.tag, f.qid, 0);
}

read(m: ref Tmsg.Read): ref Rmsg
{
	f := getfid(m.fid);
	if(f == nil)
		return rerror(m.tag, Ebadfid);
	if(!f.open)
		return rerror(m.tag, Enotopen);
	if(f.qid.qtype & Sys->QTDIR)
		return dirread(f, m);
	n := m.count;
	if(n > Maxread)
		n = Maxread;
	(data, err) := lread(f.path, m.offset, n);
	if(err != nil)
		return rerror(m.tag, err);
	return ref Rmsg.Read(m.tag, data);
}

dirread(f: ref Fid, m: ref Tmsg.Read): ref Rmsg
{
	if(m.offset == big 0 || f.dirbuf == nil){
		(buf, err) := lreaddir(f.path);
		if(err != nil)
			return rerror(m.tag, err);
		f.dirbuf = buf;
	}
	o := int m.offset;
	if(o >= len f.dirbuf)
		return ref Rmsg.Read(m.tag, array[0] of byte);
	# whole entries only
	e := o;
	while(e+2 <= len f.dirbuf){
		sz := 2 + (int f.dirbuf[e] | (int f.dirbuf[e+1] << 8));
		if(e+sz-o > m.count || e+sz > len f.dirbuf)
			break;
		e += sz;
	}
	return ref Rmsg.Read(m.tag, f.dirbuf[o:e]);
}

stat(m: ref Tmsg.Stat): ref Rmsg
{
	f := getfid(m.fid);
	if(f == nil)
		return rerror(m.tag, Ebadfid);
	(d, err) := lstat(f.path);
	if(err != nil)
		return rerror(m.tag, err);
	return ref Rmsg.Stat(m.tag, *d);
}

#
# The Lethe side: one clear request at a time.
#

p16(a: array of byte, o: int, v: int): int
{
	a[o] = byte v;
	a[o+1] = byte (v>>8);
	return o+2;
}

p32(a: array of byte, o: int, v: int): int
{
	a[o] = byte v;
	a[o+1] = byte (v>>8);
	a[o+2] = byte (v>>16);
	a[o+3] = byte (v>>24);
	return o+4;
}

p64(a: array of byte, o: int, v: big): int
{
	o = p32(a, o, int v);
	return p32(a, o, int (v>>32));
}

pstr(a: array of byte, o: int, s: string): int
{
	b := array of byte s;
	o = p16(a, o, len b);
	a[o:] = b;
	return o+len b;
}

g16(a: array of byte, o: int): int
{
	return int a[o] | (int a[o+1] << 8);
}

g32(a: array of byte, o: int): int
{
	return int a[o] | (int a[o+1] << 8) | (int a[o+2] << 16) | (int a[o+3] << 24);
}

g64(a: array of byte, o: int): big
{
	return (big g32(a, o) & big 16rFFFFFFFF) | (big g32(a, o+4) << 32);
}

gqid(a: array of byte, o: int): Qid
{
	return Qid(g64(a, o+5), g32(a, o+1), int a[o]);
}

# gstr returns the string at o and the offset after it, or -1 if it does not fit
gstr(a: array of byte, o: int): (string, int)
{
	if(o+2 > len a)
		return (nil, -1);
	n := g16(a, o);
	if(o+2+n > len a)
		return (nil, -1);
	return (string a[o+2:o+2+n], o+2+n);
}

readn(fd: ref Sys->FD, a: array of byte): int
{
	for(n := 0; n < len a; ){
		m := sys->read(fd, a[n:], len a - n);
		if(m <= 0)
			return -1;
		n += m;
	}
	return n;
}

# exchange sends one frame and returns the reply's header and body
exchange(typ: int, body: array of byte): (array of byte, array of byte, string)
{
	id := ++lid;
	f := array[10+len body] of byte;
	p32(f, 0, len f);
	f[4] = byte 1;
	f[5] = byte typ;
	p32(f, 6, id);
	f[10:] = body;
	return send(f);
}

send(f: array of byte): (array of byte, array of byte, string)
{
	if(sys->write(lfd, f, len f) != len f)
		return (nil, nil, sys->sprint("lethe write: %r"));
	hdr := array[10] of byte;
	if(readn(lfd, hdr) < 0)
		return (nil, nil, "lethe: connection closed");
	size := g32(hdr, 0);
	if(size < 10 || size > Maxframe || int hdr[4] != 1 || g32(hdr, 6) != g32(f, 6))
		return (nil, nil, Ebadmsg);
	body := array[size-10] of byte;
	if(readn(lfd, body) < 0)
		return (nil, nil, "lethe: connection closed");
	if(int hdr[5] == Rerror){
		(e, o) := gstr(body, 0);
		if(o != len body || e == nil)
			return (nil, nil, Ebadmsg);
		return (nil, nil, e);
	}
	return (hdr, body, nil);
}

# rpc sends one inner request (op and fields) and returns the inner reply
# with the expected op, or the error string.
rpc(req: array of byte, want: int): (array of byte, string)
{
	reply: array of byte;
	err: string;
	if(clear){
		hdr, body: array of byte;
		(hdr, body, err) = exchange(Tclear, req);
		if(err == nil && int hdr[5] != Rclear)
			err = Ebadmsg;
		reply = body;
	}else{
		(reply, err) = sealed(req);
		case err {
		"ticket expired" or "unknown ticket key" or "bad ticket" or "request expired" =>
			# a new ticket (and a new reading of the server's clock), once
			err = authenticate();
			if(err == nil)
				(reply, err) = sealed(req);
		}
	}
	if(err != nil)
		return (nil, err);
	if(len reply < 1)
		return (nil, Ebadmsg);
	if(int reply[0] == ORerror){
		(e, o) := gstr(reply, 1);
		if(o != len reply || e == nil)
			return (nil, Ebadmsg);
		return (nil, e);
	}
	if(int reply[0] != want)
		return (nil, Ebadmsg);
	return (reply[1:], nil);
}

#
# The sealed mode.
#

cat(a, b: array of byte): array of byte
{
	c := array[len a + len b] of byte;
	c[0:] = a;
	c[len a:] = b;
	return c;
}

readfile(name: string): string
{
	fd := sys->open(name, Sys->OREAD);
	if(fd == nil)
		fatal(sys->sprint("%s: %r", name));
	buf := array[256] of byte;
	n := sys->read(fd, buf, len buf);
	if(n <= 0)
		fatal(sys->sprint("%s: empty", name));
	return string buf[0:n];
}

# a seed file is 32 bytes, or 64 hex digits and a newline
readseed(name: string): array of byte
{
	fd := sys->open(name, Sys->OREAD);
	if(fd == nil)
		fatal(sys->sprint("%s: %r", name));
	buf := array[128] of byte;
	n := sys->read(fd, buf, len buf);
	if(n == 32)
		return buf[0:32];
	if(n >= 64){
		a := array[32] of byte;
		for(i := 0; i < 32; i++){
			hi := hexv(int buf[2*i]);
			lo := hexv(int buf[2*i+1]);
			if(hi < 0 || lo < 0)
				fatal(name + ": not a seed file");
			a[i] = byte ((hi<<4)|lo);
		}
		return a;
	}
	fatal(name + ": not a seed file");
	return nil;
}

hexv(c: int): int
{
	if(c >= '0' && c <= '9')
		return c-'0';
	if(c >= 'a' && c <= 'f')
		return c-'a'+10;
	if(c >= 'A' && c <= 'F')
		return c-'A'+10;
	return -1;
}

sha256(a: array of byte): array of byte
{
	d := array[32] of byte;
	crypt->sha256(a, len a, d, nil);
	return d;
}

# expand is HKDF-Expand(prk, info, 32): one block of HMAC-SHA256
expand(prk: array of byte, info: string): array of byte
{
	ipad := array[64] of {* => byte 16r36};
	opad := array[64] of {* => byte 16r5c};
	for(i := 0; i < len prk; i++){
		ipad[i] ^= prk[i];
		opad[i] ^= prk[i];
	}
	inner := sha256(cat(ipad, cat(array of byte info, array[1] of {byte 1})));
	return sha256(cat(opad, inner));
}

# authenticate gets a ticket and its keys: one round trip
authenticate(): string
{
	e := random->randombuf(Random->ReallyRandom, 32);
	ephc := crypt->x25519base(e);
	pub := crypt->ed25519pub(seed);
	ek, dk: array of byte;
	context := "lethe1 auth";
	if(!classical){
		(ek, dk) = crypt->mlkem768keygen();
		context = "lethe2 auth";
	}else
		ek = array[0] of byte;

	# what both the signature and the frame hold, after the context:
	# eph_c [ek] rights prefix s[2] uname s[2] kind body s[2]
	ub := array of byte uname;
	m := array[32+len ek+1+(2+1)+(2+len ub)+1+(2+32)] of byte;
	m[0:] = ephc;
	m[32:] = ek;
	o := 32+len ek;
	m[o++] = byte Rread;
	o = pstr(m, o, "/");
	o = pstr(m, o, uname);
	m[o++] = byte 0;	# kind 0: a bare Ed25519 public key
	o = p16(m, o, 32);
	m[o:] = pub;
	signed := cat(cat(array of byte context, array[1] of {byte 0}), m);
	sig := crypt->ed25519sign(seed, signed);
	if(sig == nil)
		return "cannot sign";

	typ := Tauth2;
	if(classical)
		typ = Tauth;
	(hdr, body, err) := exchange(typ, cat(m, sig));
	if(err != nil)
		return err;
	# Rauth  = eph_s[32] nonce[24] sealed(grant)
	# Rauth2 = eph_s[32] ct[1088] nonce[24] sealed(grant)
	nct := 0;
	if(!classical)
		nct = Crypt->MLKEM768ctlen;
	if(classical && int hdr[5] != Rauth || !classical && int hdr[5] != Rauth2)
		return "no post-quantum key offered";
	if(len body < 32+nct+Noncelen+Taglen)
		return Ebadmsg;
	ephs := body[0:32];
	ct := body[32:32+nct];
	nonce := body[32+nct:32+nct+Noncelen];
	x := crypt->x25519(e, ephs);
	zero := 1;
	for(i := 0; i < len x; i++)
		if(x[i] != byte 0)
			zero = 0;
	if(zero)
		return "bad server key";
	ikm := x;
	label := "lethe1 master";
	if(!classical){
		k := crypt->mlkem768decap(dk, ct);
		if(k == nil)
			return Ebadmsg;
		ikm = cat(k, x);	# the ML-KEM secret first
		label = "lethe2 master";
	}
	transcript := cat(cat(signed, ephs), ct);
	master := crypt->hkdfsha256(sha256(transcript), ikm, array of byte label, 32);
	nc2s := expand(master, "lethe1 c2s");
	ns2c := expand(master, "lethe1 s2c");
	grant := crypt->xchachapolyopen(ns2c, nonce, cat(cat(hdr, ephs), ct), body[32+nct+Noncelen:]);
	if(grant == nil)
		return "bad record mac";
	# grant = now u64 expires u64 rights u8 prefix s[2] ticket s[2]
	if(len grant < 8+8+1+2)
		return Ebadmsg;
	now := g64(grant, 0);
	(nil, p) := gstr(grant, 17);
	if(p < 0 || p+2 > len grant)
		return Ebadmsg;
	n := g16(grant, p);
	if(p+2+n != len grant)
		return Ebadmsg;
	ticket = grant[p+2:];
	c2s = nc2s;
	s2c = ns2c;
	skew = int now - daytime->now();
	return nil;
}

# sealed sends one request under the ticket and opens the reply
sealed(req: array of byte): (array of byte, string)
{
	# plain = time u64 || request
	plain := array[8+len req] of byte;
	p64(plain, 0, big (daytime->now() + skew));
	plain[8:] = req;
	nonce := random->randombuf(Random->NotQuiteRandom, Noncelen);
	# Treq = ticket s[2] nonce[24] seal(c2s, header || ticket, plain)
	id := ++lid;
	f := array[10+2+len ticket+Noncelen+len plain+Taglen] of byte;
	p32(f, 0, len f);
	f[4] = byte 1;
	f[5] = byte Treq;
	p32(f, 6, id);
	o := p16(f, 10, len ticket);
	f[o:] = ticket;
	o += len ticket;
	f[o:] = nonce;
	o += Noncelen;
	f[o:] = crypt->xchachapolyseal(c2s, nonce, cat(f[0:10], ticket), plain);
	(hdr, body, err) := send(f);
	if(err != nil)
		return (nil, err);
	# Rreq = nonce[24] seal(s2c, header || request nonce, reply)
	if(int hdr[5] != Rreq || len body < Noncelen+Taglen)
		return (nil, Ebadmsg);
	reply := crypt->xchachapolyopen(s2c, body[0:Noncelen], cat(hdr, nonce), body[Noncelen:]);
	if(reply == nil)
		return (nil, "bad record mac");
	return (reply, nil);
}

lstat(path: string): (ref Dir, string)
{
	req := array[1+2+len array of byte path] of byte;
	req[0] = byte OTstat;
	pstr(req, 1, path);
	(r, err) := rpc(req, ORstat);
	if(err != nil)
		return (nil, err);
	(n, d) := styx->unpackdir(r);
	if(n != len r)
		return (nil, Ebadmsg);
	return (ref d, nil);
}

lread(path: string, offset: big, count: int): (array of byte, string)
{
	req := array[1+2+len array of byte path+8+4+1+4] of byte;
	req[0] = byte OTread;
	o := pstr(req, 1, path);
	o = p64(req, o, offset);
	o = p32(req, o, count);
	req[o++] = byte 0;	# cond: no cached copy
	p32(req, o, 0);
	(r, err) := rpc(req, ORread);
	if(err != nil)
		return (nil, err);
	# qid[13] unchanged u8 count u32 data
	if(len r < 13+1+4)
		return (nil, Ebadmsg);
	n := g32(r, 14);
	if(n < 0 || 18+n != len r)
		return (nil, Ebadmsg);
	return (r[18:], nil);
}

# lreaddir returns every entry of a directory, as packed Styx stat entries
lreaddir(path: string): (array of byte, string)
{
	all := array[0] of byte;
	cookie := "";
	for(;;){
		req := array[1+2+len array of byte path+2+len array of byte cookie+4] of byte;
		req[0] = byte OTreaddir;
		o := pstr(req, 1, path);
		o = pstr(req, o, cookie);
		p32(req, o, Maxread);
		(r, err) := rpc(req, ORreaddir);
		if(err != nil)
			return (nil, err);
		# qid[13] cookie s[2] count u32 entries
		if(len r < 13)
			return (nil, Ebadmsg);
		(ck, p) := gstr(r, 13);
		if(p < 0 || p+4 > len r)
			return (nil, Ebadmsg);
		n := g32(r, p);
		if(n < 0 || p+4+n != len r)
			return (nil, Ebadmsg);
		na := array[len all + n] of byte;
		na[0:] = all;
		na[len all:] = r[p+4:];
		all = na;
		if(ck == nil || ck == "")
			break;
		cookie = ck;
	}
	return (all, nil);
}

# lwalk walks names from path and returns the qids of the names walked;
# the error is set if not all of them were.
lwalk(path: string, names: array of string): (array of Qid, string)
{
	n := 1+2+len array of byte path+2;
	for(i := 0; i < len names; i++)
		n += 2+len array of byte names[i];
	req := array[n] of byte;
	req[0] = byte OTwalk;
	o := pstr(req, 1, path);
	o = p16(req, o, len names);
	for(i = 0; i < len names; i++)
		o = pstr(req, o, names[i]);
	(r, err) := rpc(req, ORwalk);
	if(err != nil)
		return (nil, err);
	# nqid u16 qid[13]*nqid ename s[2] stat[n]
	if(len r < 2)
		return (nil, Ebadmsg);
	nq := g16(r, 0);
	if(nq > len names || 2+13*nq+2 > len r)
		return (nil, Ebadmsg);
	qids := array[nq] of Qid;
	for(i = 0; i < nq; i++)
		qids[i] = gqid(r, 2+13*i);
	(ename, nil) := gstr(r, 2+13*nq);
	if(nq < len names && (ename == nil || ename == ""))
		ename = "file does not exist";
	if(nq == len names)
		ename = nil;
	return (qids, ename);
}
