implement Lethefs;

#
# lethefs -A [-D] addr mtpt
#
# A Lethe client (docs/lethe.md in Purgatorio, protocol lethe1): dials a
# lethed, and presents its read-only tree at mtpt by serving Styx on a pipe.
# The server keeps no state; the fid table Styx needs lives here.
# Only the clear mode (-A, Tclear/Rclear) is implemented.
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

Lethefs: module
{
	init: fn(nil: ref Draw->Context, args: list of string);
};

# outer frame types
Rerror:	con 5;
Tclear:	con 9;
Rclear:	con 10;

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

	clear := 0;
	arg->init(args);
	arg->setusage("lethefs -A [-D] addr mtpt");
	while((o := arg->opt()) != 0)
		case o {
		'A' =>	clear = 1;
		'D' =>	debug = 1;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 2)
		arg->usage();
	if(!clear)
		fatal("only the clear mode (-A) is implemented");
	addr := dial->netmkaddr(hd args, "tcp", "5640");
	mtpt := hd tl args;

	c := dial->dial(addr, nil);
	if(c == nil)
		fatal(sys->sprint("dial %s: %r", addr));
	lfd = c.dfd;

	# fail now, not at the first walk, if the server refuses clear requests
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

# rpc sends one inner request (op and fields) and returns the inner reply
# with the expected op, or the error string.
rpc(req: array of byte, want: int): (array of byte, string)
{
	id := ++lid;
	f := array[10+len req] of byte;
	p32(f, 0, len f);
	f[4] = byte 1;
	f[5] = byte Tclear;
	p32(f, 6, id);
	f[10:] = req;
	if(sys->write(lfd, f, len f) != len f)
		return (nil, sys->sprint("lethe write: %r"));
	hdr := array[10] of byte;
	if(readn(lfd, hdr) < 0)
		return (nil, "lethe: connection closed");
	size := g32(hdr, 0);
	if(size < 10 || size > Maxframe || int hdr[4] != 1 || g32(hdr, 6) != id)
		return (nil, Ebadmsg);
	body := array[size-10] of byte;
	if(readn(lfd, body) < 0)
		return (nil, "lethe: connection closed");
	case int hdr[5] {
	Rerror =>
		(e, o) := gstr(body, 0);
		if(o != len body)
			return (nil, Ebadmsg);
		return (nil, e);
	Rclear =>
		if(len body < 1)
			return (nil, Ebadmsg);
		if(int body[0] == ORerror){
			(e, o) := gstr(body, 1);
			if(o != len body)
				return (nil, Ebadmsg);
			return (nil, e);
		}
		if(int body[0] != want)
			return (nil, Ebadmsg);
		return (body[1:], nil);
	}
	return (nil, Ebadmsg);
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
