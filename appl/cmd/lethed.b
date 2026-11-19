implement Lethed;

#
# lethed -A [-a addr] root
#
# A Lethe server (docs/lethe.md in Purgatorio, protocol lethe1): serves the
# tree at root, read-only, keeping no state between requests. Because root
# is a name in this process's name space, it can be anything mountable.
# Only the clear mode (-A, Tclear/Rclear) is implemented; requests are
# answered as the user none, so files need the "other" permission bits.
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
include "readdir.m";
	readdir: Readdir;

Lethed: module
{
	init: fn(nil: ref Draw->Context, args: list of string);
};

# outer frame types
Tauth:	con 1;
Treq:	con 3;
Rerror:	con 5;
Tclear:	con 9;
Rclear:	con 10;
Tauth2:	con 11;
Treqref:	con 13;

# inner ops
OTstat:	con 16r10;
ORstat:	con 16r11;
OTread:	con 16r12;
ORread:	con 16r13;
OTreaddir:	con 16r14;
ORreaddir:	con 16r15;
OTdigest:	con 16r16;
OTwalk:	con 16r18;
ORwalk:	con 16r19;
ORerror:	con 16r7f;

Maxframe:	con 65536;
Maxread:	con 32768;
Maxwalk:	con 64;
Maxelem:	con 255;
Maxpath:	con 1024;

Enotexist:	con "file does not exist";
Eperm:	con "permission denied";
Enotdir:	con "not a directory";
Eisdir:	con "file is a directory";
Ename:	con "file name syntax";
Ebadmsg:	con "bad lethe message";
Enotimpl:	con "not implemented";

root: string;
stderr: ref Sys->FD;
verbose := 0;

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	stderr = sys->fildes(2);
	styx = load Styx Styx->PATH;
	dial = load Dial Dial->PATH;
	readdir = load Readdir Readdir->PATH;
	arg := load Arg Arg->PATH;
	if(styx == nil || dial == nil || readdir == nil || arg == nil)
		fatal("cannot load modules");
	styx->init();

	clear := 0;
	addr := "tcp!*!5640";
	arg->init(args);
	arg->setusage("lethed -A [-v] [-a addr] root");
	while((o := arg->opt()) != 0)
		case o {
		'A' =>	clear = 1;
		'v' =>	verbose = 1;
		'a' =>	addr = arg->earg();
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1)
		arg->usage();
	if(!clear)
		fatal("only the clear mode (-A) is implemented, and a server that trusts no keys does not start");
	root = hd args;
	while(len root > 1 && root[len root-1] == '/')
		root = root[0:len root-1];
	(ok, d) := sys->stat(root);
	if(ok < 0 || (d.mode & Sys->DMDIR) == 0)
		fatal(sys->sprint("%s: not a directory", root));

	c := dial->announce(dial->netmkaddr(addr, "tcp", "5640"));
	if(c == nil)
		fatal(sys->sprint("announce %s: %r", addr));
	sys->fprint(stderr, "lethed: listening on %s\n", addr);
	spawn listener(c);
}

fatal(s: string)
{
	sys->fprint(stderr, "lethed: %s\n", s);
	raise "fail:error";
}

listener(c: ref Dial->Connection)
{
	for(;;){
		nc := dial->listen(c);
		if(nc == nil){
			sys->fprint(stderr, "lethed: listen: %r\n");
			return;
		}
		fd := dial->accept(nc);
		if(fd != nil)
			spawn conn(fd);
	}
}

#
# little-endian packing
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

pqid(a: array of byte, o: int, q: Qid): int
{
	a[o] = byte q.qtype;
	o = p32(a, o+1, q.vers);
	o = p32(a, o, int q.path);
	return p32(a, o, int (q.path>>32));
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

# gstr returns the string at o and the offset after it, or -1 if it does not fit
gstr(a: array of byte, o: int): (string, int)
{
	if(o < 0 || o+2 > len a)
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

#
# one connection: a frame in, a frame out
#

conn(fd: ref Sys->FD)
{
	hdr := array[10] of byte;
	for(;;){
		if(readn(fd, hdr) < 0)
			return;
		size := g32(hdr, 0);
		if(size < 10 || size > Maxframe){
			reply(fd, Rerror, 0, estr(Ebadmsg));
			return;
		}
		body := array[size-10] of byte;
		if(readn(fd, body) < 0)
			return;
		id := g32(hdr, 6);
		if(int hdr[4] != 1){
			reply(fd, Rerror, id, estr("unknown lethe version"));
			continue;
		}
		case int hdr[5] {
		Tclear =>
			reply(fd, Rclear, id, request(body));
		Tauth or Tauth2 =>
			reply(fd, Rerror, id, estr("authentication not required"));
		Treq or Treqref =>
			reply(fd, Rerror, id, estr("bad ticket"));
		* =>
			reply(fd, Rerror, id, estr(Ebadmsg));
		}
	}
}

reply(fd: ref Sys->FD, typ, id: int, body: array of byte)
{
	f := array[10+len body] of byte;
	p32(f, 0, len f);
	f[4] = byte 1;
	f[5] = byte typ;
	p32(f, 6, id);
	f[10:] = body;
	sys->write(fd, f, len f);
}

# estr is the body of an outer Rerror: ename s[2]
estr(e: string): array of byte
{
	b := array of byte e;
	a := array[2+len b] of byte;
	p16(a, 0, len b);
	a[2:] = b;
	return a;
}

# ierr is an inner Rerror
ierr(e: string): array of byte
{
	b := array of byte e;
	a := array[1+2+len b] of byte;
	a[0] = byte ORerror;
	p16(a, 1, len b);
	a[3:] = b;
	return a;
}

request(b: array of byte): array of byte
{
	if(len b < 1)
		return ierr(Ebadmsg);
	op := int b[0];
	if(verbose)
		sys->fprint(stderr, "lethed: op %#x, %d bytes\n", op, len b);
	case op {
	OTstat =>
		(path, o) := gstr(b, 1);
		if(o != len b)
			return ierr(Ebadmsg);
		return rstat(path);
	OTread =>
		(path, o) := gstr(b, 1);
		if(o < 0 || o+8+4+1+4 != len b)
			return ierr(Ebadmsg);
		return rread(path, g64(b, o), g32(b, o+8), int b[o+12], g32(b, o+13));
	OTreaddir =>
		(path, o) := gstr(b, 1);
		(cookie, o2) := gstr(b, o);
		if(o2 < 0 || o2+4 != len b)
			return ierr(Ebadmsg);
		return rreaddir(path, cookie, g32(b, o2));
	OTwalk =>
		(path, o) := gstr(b, 1);
		if(o < 0 || o+2 > len b)
			return ierr(Ebadmsg);
		n := g16(b, o);
		o += 2;
		if(n > Maxwalk)
			return ierr(Ebadmsg);
		names := array[n] of string;
		for(i := 0; i < n; i++){
			(names[i], o) = gstr(b, o);
			if(o < 0)
				return ierr(Ebadmsg);
		}
		if(o != len b)
			return ierr(Ebadmsg);
		return rwalk(path, names);
	}
	if(op >= 16r20 && op <= 16r2f)
		return ierr(Eperm);	# writes: the tree is read-only
	return ierr(Enotimpl);
}

#
# names and permission
#

okelem(s: string): int
{
	if(s == nil || s == "" || s == "." || s == ".." || len array of byte s > Maxelem)
		return 0;
	for(i := 0; i < len s; i++)
		if(s[i] == '/' || s[i] == 0)
			return 0;
	return 1;
}

# split checks a path and returns its elements; ok is 0 for a bad path
split(path: string): (int, list of string)
{
	if(path == nil || len path == 0 || path[0] != '/' || len array of byte path > Maxpath)
		return (0, nil);
	if(path == "/")
		return (1, nil);
	if(path[len path-1] == '/')
		return (0, nil);
	(nil, l) := sys->tokenize(path, "/");
	n := 0;
	for(t := l; t != nil; t = tl t){
		if(!okelem(hd t))
			return (0, nil);
		n += 1 + len hd t;
	}
	if(n != len path)	# an empty element (//) was dropped by tokenize
		return (0, nil);
	return (1, l);
}

# syserr turns the system's error string into the bare Inferno string
syserr(): string
{
	e := sys->sprint("%r");
	if(len e > 0 && e[0] == '\''){
		for(i := 1; i < len e; i++)
			if(e[i] == '\''){
				if(i+2 <= len e)
					e = e[i+2:];
				break;
			}
	}
	if(e == "does not exist" || e == "directory entry not found" || e == "No such file or directory")
		return Enotexist;
	return e;
}

# lookup stats path as the user none may: every directory above it must be
# searchable by others. It returns the name in this name space and the entry.
lookup(path: string): (string, ref Dir, string)
{
	(ok, elems) := split(path);
	if(!ok)
		return (nil, nil, Ename);
	name := root;
	(r, d) := sys->stat(name);
	if(r < 0)
		return (nil, nil, syserr());
	for(; elems != nil; elems = tl elems){
		if((d.mode & Sys->DMDIR) == 0)
			return (nil, nil, Enotdir);
		if((d.mode & 8r001) == 0)
			return (nil, nil, Eperm);
		name += "/" + hd elems;
		(r, d) = sys->stat(name);
		if(r < 0)
			return (nil, nil, syserr());
	}
	return (name, ref d, nil);
}

#
# the operations
#

rstat(path: string): array of byte
{
	(nil, d, err) := lookup(path);
	if(err != nil)
		return ierr(err);
	if(path == "/")
		d.name = "/";
	st := styx->packdir(*d);
	a := array[1+len st] of byte;
	a[0] = byte ORstat;
	a[1:] = st;
	return a;
}

rread(path: string, offset: big, count, cond, vers: int): array of byte
{
	(name, d, err) := lookup(path);
	if(err != nil)
		return ierr(err);
	if(d.mode & Sys->DMDIR)
		return ierr(Eisdir);
	if((d.mode & 8r004) == 0)
		return ierr(Eperm);
	if(count < 0 || count > Maxread)
		count = Maxread;
	data := array[0] of byte;
	unchanged := 0;
	if(cond == 1 && vers == d.qid.vers)
		unchanged = 1;
	else{
		fd := sys->open(name, Sys->OREAD);
		if(fd == nil)
			return ierr(syserr());
		# the entry and the data must be of one version
		(r, nd) := sys->fstat(fd);
		if(r < 0)
			return ierr(syserr());
		d = ref nd;
		buf := array[count] of byte;
		n := 0;
		while(n < count){
			m := sys->pread(fd, buf[n:], count-n, offset+big n);
			if(m < 0)
				return ierr(syserr());
			if(m == 0)
				break;
			n += m;
		}
		data = buf[0:n];
	}
	a := array[1+13+1+4+len data] of byte;
	a[0] = byte ORread;
	o := pqid(a, 1, d.qid);
	a[o++] = byte unchanged;
	o = p32(a, o, len data);
	a[o:] = data;
	return a;
}

rreaddir(path, cookie: string, count: int): array of byte
{
	(name, d, err) := lookup(path);
	if(err != nil)
		return ierr(err);
	if((d.mode & Sys->DMDIR) == 0)
		return ierr(Enotdir);
	if((d.mode & 8r004) == 0)
		return ierr(Eperm);
	if(count < 0 || count > Maxread)
		count = Maxread;
	# names in byte order, so a page resumes after the last name sent
	(dirs, n) := readdir->init(name, Readdir->NAME|Readdir->COMPACT);
	if(n < 0)
		return ierr(syserr());
	buf := array[count] of byte;
	used := 0;
	last := "";
	more := 0;
	for(i := 0; i < n; i++){
		if(cookie != nil && cookie != "" && dirs[i].name <= cookie)
			continue;
		st := styx->packdir(*dirs[i]);
		if(used + len st > count){
			more = 1;
			break;
		}
		buf[used:] = st;
		used += len st;
		last = dirs[i].name;
	}
	if(!more)
		last = "";
	lb := array of byte last;
	a := array[1+13+2+len lb+4+used] of byte;
	a[0] = byte ORreaddir;
	o := pqid(a, 1, d.qid);
	o = p16(a, o, len lb);
	a[o:] = lb;
	o += len lb;
	o = p32(a, o, used);
	a[o:] = buf[0:used];
	return a;
}

rwalk(path: string, names: array of string): array of byte
{
	(name, d, err) := lookup(path);
	if(err != nil)
		return ierr(err);	# a failure at path itself is the plain error
	if(path == "/")
		d.name = "/";
	qids := array[len names] of Qid;
	nq := 0;
	ename := "";
	for(i := 0; i < len names; i++){
		if(!okelem(names[i])){
			ename = Ename;
			break;
		}
		if((d.mode & Sys->DMDIR) == 0){
			ename = Enotdir;
			break;
		}
		if((d.mode & 8r001) == 0){
			ename = Eperm;
			break;
		}
		name += "/" + names[i];
		(r, nd) := sys->stat(name);
		if(r < 0){
			ename = syserr();
			break;
		}
		d = ref nd;
		qids[nq++] = d.qid;
	}
	st := array[0] of byte;
	if(ename == "")
		st = styx->packdir(*d);
	eb := array of byte ename;
	a := array[1+2+13*nq+2+len eb+len st] of byte;
	a[0] = byte ORwalk;
	o := p16(a, 1, nq);
	for(i = 0; i < nq; i++)
		o = pqid(a, o, qids[i]);
	o = p16(a, o, len eb);
	a[o:] = eb;
	o += len eb;
	a[o:] = st;
	return a;
}
