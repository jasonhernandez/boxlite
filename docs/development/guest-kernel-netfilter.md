# Guest kernel: netfilter

## Why

The stock guest kernel is built with `# CONFIG_NETFILTER is not set`. A box
therefore has no `/proc/sys/net/netfilter`, no `ip_tables`/`nf_tables` backend,
and any `iptables` call fails before it does anything:

```
$ boxlite exec $BOX -- iptables --version
iptables: Failed to initialize nft: Protocol not supported
```

That is what stops `dockerd` inside a box — it cannot register its `bridge`
driver — and anything else that firewalls per network namespace.

## The change

`src/deps/libkrun-sys/kernel-config/netfilter.config` is a Kconfig fragment
merged into the vendored libkrunfw config by `libkrun-sys`'s build script
before a from-source kernel build. It turns on netfilter core, `nf_tables`
(including `NFT_COMPAT`, which is what `iptables-nft` actually drives), the
xtables matches Docker uses (`addrtype`, `conntrack`, `multiport`, …), the
IPv4 and IPv6 tables, and `BRIDGE`/`BRIDGE_NETFILTER` for `docker0`.

The fragment lives in *this* repo, not in the libkrunfw submodule, so the
config is versioned with the code that depends on it and no submodule pointer
has to move.

The guest kernel has no loadable-module support (`# CONFIG_MODULES is not
set`), so every symbol is built in.

## Building it

`CONFIG_POSIX_MQUEUE` is in the fragment for a different reason: it is not a
netfilter symbol, but runc's default OCI spec always mounts `mqueue` at
`/dev/mqueue`, so without it every `docker run` fails with
`mount src=mqueue ... no such device` *after* the netfilter work is done.

## What this unblocks

With the rebuilt kernel and a `--privileged` box, Docker runs inside a box:
`dockerd` starts on its defaults (overlay2, iptables on, `docker0` bridge),
`docker build` works, nested containers get NAT'd outbound networking through
`docker0`, and `-p` publishes via a `DNAT` rule.

`--privileged` is needed *as well as* the kernel. Two different layers block
Docker and both have to move:

| layer | symptom | fix |
|---|---|---|
| guest kernel | `iptables: Failed to initialize nft: Protocol not supported` | this fragment |
| container | `/proc/sys/net/ipv4/ip_forward: read-only file system`, `mkdir /sys/fs/cgroup/docker: read-only file system` | `--privileged` (OCI `readonlyPaths` and the `rro` on the `/sys` bind) |

## Building it

The fragment is only applied on a from-source kernel build, which is opt-in:

```
BOXLITE_BUILD_LIBKRUNFW=1 cargo build --release -p boxlite-cli
```

**Without `BOXLITE_BUILD_LIBKRUNFW`, Linux downloads a pre-compiled
`libkrunfw.so` from a pinned release and the fragment has no effect at all.**
That is the default path, and it still ships a kernel with no netfilter.

`verify_kernel_config_fragment` fails the build if the kernel that came out is
missing any symbol the fragment asked for. The usual cause is a kernel tree
left over from an earlier build: libkrunfw's Makefile copies the config only
when it first unpacks the tree, so `make clean` in
`src/deps/libkrun-sys/vendor/libkrunfw` is the fix.

## Cost

Measured on x86_64, Linux 6.12.87, both kernels built from the same tree with
the same gcc 14.2, `boxlite start` interleaved A/B, 20 samples each:

| | stock | +netfilter | delta |
|---|---|---|---|
| `vmlinux` | 29,097,288 B | 29,391,208 B | +293,920 B (+1.01 %) |
| `libkrunfw.so.5` | 21,366,360 B | 21,431,896 B | +65,536 B (+0.31 %) |
| `boxlite start`, median | 404.5 ms | 403.0 ms | −1.5 ms (σ ≈ 17 ms) |
| guest `/proc/uptime` at first exec, median | 0.240 s | 0.240 s | 0 ms |

The boot-time difference is inside the run-to-run noise: there is no measurable
boot cost. The library grows by 64 KiB.

Compare the two kernels with the *same* compiler. A netfilter kernel built by
one gcc against the shipped release built by another shows a difference that is
the toolchain, not the config.

### Not enabled

`CONFIG_XFRM_USER` stays off, so `dockerd` logs `Could not load necessary
modules for IPSEC rules: protocol not supported` at every start. It is a
warning, not a failure — it only affects encrypted swarm overlay networks.

## Maintenance

This is a config fork of an upstream kernel. Every libkrunfw bump re-applies
the fragment against a new base config; symbols that upstream renames or folds
away will fail the post-build verification rather than silently vanish.
