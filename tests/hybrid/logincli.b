implement Logincli;
# logincli [-1] addr user password keyfile: Login->login over the network, then save the authinfo
include "sys.m"; sys: Sys;
include "draw.m";
include "keyring.m";
include "security.m";
Logincli: module { init: fn(nil: ref Draw->Context, args: list of string); };
init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	kr := load Keyring Keyring->PATH;
	login := load Login Login->PATH;
	args = tl args;
	pre := "";
	if(hd args == "-1"){
		pre = "v1 ";
		args = tl args;
	}
	addr := hd args; user := hd tl args; pw := hd tl tl args; file := hd tl tl tl args;
	(err, info) := login->login(user, pw, pre + addr);
	if(info == nil){
		sys->print("LOGIN failed: %s\n", err);
		raise "fail:login";
	}
	sys->create(file, Sys->OWRITE, 8r600);
	if(kr->writeauthinfo(file, info) < 0){
		sys->print("LOGIN can't write %s: %r\n", file);
		raise "fail:write";
	}
	sys->print("LOGIN ok: certificate for %s from %s (%s)\n", info.mypk.owner, info.cert.signer, info.cert.sa.name);
}
