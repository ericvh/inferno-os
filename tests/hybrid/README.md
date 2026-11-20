# tests/hybrid: the hybrid authentication work in a native kernel

`run.sh` is an Inferno shell script that runs, inside a booted kernel:
`auth/crypttest` (60 known-answer checks), `auth/authtest` (30 handshake
cases), `auth/logintest` (46 login cases), then over the loopback: a mount
with hybrid Ed25519 + ML-DSA-65 certificates (and one refused), Lethe sealed
and with a hybrid certificate, factotum's infauth, and a password login
followed by a mount with the certificate it issued.

The keys here are throwaway test keys.

    tests/hybrid/stage.sh            # copy the fixtures into the baked root
    make -C os/amd64 HWTARG=pc64 USERSPACE=headless
    (sleep 25; echo 'sh /lib/hybtest/run.sh'; sleep 500) |
        qemu-system-x86_64 -M q35 -m 1024 -enable-kvm -cpu host -nographic \
            -kernel os/amd64/ipc64.elf

    make -C os/aarch64 CROSS=aarch64-linux-gnu- HWTARG=virt64 USERSPACE=headless
    (sleep 60; echo 'sh /lib/hybtest/run.sh'; sleep 1700) |
        qemu-system-aarch64 -M virt -cpu cortex-a53 -m 1024 -nographic -nic none \
            -global virtio-mmio.force-legacy=false -device virtio-rng-device \
            -kernel os/aarch64/ivirt64.elf

`echo 1 > /dev/jit` before the script runs it under the JIT. Each test
prints a count; the K lines print what they read through the mounts.
`tests/hybrid/unstage.sh` removes the fixtures from the root trees again.
