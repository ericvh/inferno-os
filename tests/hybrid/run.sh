# Run by benchinit at boot.
load std
echo auth-kernel-start
echo random: `{dd -if /dev/random -bs 64 -count 1 | md5sum}
auth/crypttest
auth/authtest
auth/logintest
bind -a '#I' /net
{echo bind loopback /dev/null; echo add 127.0.0.1 255.0.0.0 127.0.0.0} > /net/ipifc/clone
mkdir /tmp/exp /tmp/mnt /tmp/lm /tmp/lh
echo hello from the kernel > /tmp/exp/greeting
dd -if /dis/sh.dis -of /tmp/exp/big >[2] /dev/null
listen -k /lib/hybtest/hysrv tcp!127.0.0.1!6700 {export /tmp/exp}
sleep 1
echo K0 a certificate from another signer is refused:
mount -k /lib/hybtest/mallory tcp!127.0.0.1!6700 /tmp/lh
mount -k /lib/hybtest/hyalice tcp!127.0.0.1!6700 /tmp/mnt
echo K1 mount, hybrid certificates: `{cat /tmp/mnt/greeting}
echo K2 sums: `{md5sum < /tmp/mnt/big} `{md5sum < /tmp/exp/big}
lethed -k /lib/hybtest/user.pub -a tcp!127.0.0.1!5640 /tmp/exp &
lethed -s /lib/hybtest/hysigners -C mldsa65 -a tcp!127.0.0.1!5641 /tmp/exp &
sleep 2
lethefs -k /lib/hybtest/user.seed -u erivan01 tcp!127.0.0.1!5640 /tmp/lm
echo K3 lethe, sealed: `{cat /tmp/lm/greeting} `{md5sum < /tmp/lm/big}
lethefs -k /lib/hybtest/hygood -u erivan01 tcp!127.0.0.1!5641 /tmp/lh
echo K4 lethe, hybrid certificate: `{cat /tmp/lh/greeting}
auth/factotum
auth/ai2key -t 'role=client' /lib/hybtest/hyalice > /mnt/factotum/ctl
auth/ai2key -t 'role=server' /lib/hybtest/hysrv > /mnt/factotum/ctl
echo K5 factotum, hybrid keys:
auth/factest
mkdir /tmp/keys /tmp/keys/alice /tmp/m2
cp /lib/hybtest/secret /tmp/keys/alice/secret
echo -n never > /tmp/keys/alice/expire
listen -A 'tcp!127.0.0.1!6710' {auth/logind -k /tmp/keys -s /lib/hybtest/hysigner}
listen -k /lib/hybtest/hysrv 'tcp!127.0.0.1!6711' {export /tmp/exp}
sleep 1
echo K6 login with a wrong password:
/dis/logincli.dis 'tcp!127.0.0.1!6710' alice 'not the password' /tmp/bad.key
echo K7 login over TCP:
/dis/logincli.dis 'tcp!127.0.0.1!6710' alice 'correct horse battery' /tmp/alice.key
mount -k /tmp/alice.key 'tcp!127.0.0.1!6711' /tmp/m2
echo K8 mount with the certificate from that login: `{cat /tmp/m2/greeting}
echo auth-kernel-done
