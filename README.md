## TLStunnel

This is a MirageOS unikernel accepting TLS connections via the public (service)
network interface on frontend-port, and proxying them using TCP via the private
network interface to backend-ip and backend-port. A client connecting to
TLStunnel has to establish a TLS connection, which payload is forwarded to the
backend service via TCP.

TLStunnel can be used for load-balancing - using multiple TLStunnel on the
frontend doing expensive crypto operations (asymmetrics TLS handshakes and
symmetric cryptography) with a single (or multiple) backend-services which
communicate via plain TCP.

Security-wise only the TLStunnel needs access to the private key of the X.509
certificate(s). When TLStunnel is configured to do client authentication, only
valid clients can access the backend service, limiting the attack surface
drastically.

## Usage

Executing TLStunnel requires two IP addresses: one is the public facing one, the
other is on the private network (where TCP connections are forwarded to).
Configuration can be done via a command-line utility on the private network. The
X.509 certificate should be available via DNS (see
[dns-primary-git](https://github.com/robur-coop/dns-primary-git) and
[dns-letsencrypt-secondary](https://github.com/robur-coop/dns-letsencrypt-secondary/)).

Let's consider your public IP address being 1.2.3.4/24 (with default gateway
1.2.3.1). You use 192.168.0.4/24 as your private network. Your DNS server is
1.2.3.5 with the key tlstunnel._update.example.org.

Starting TLStunnel:

```bash
$ truncate -s 1m /var/db/tlstunnel
$ solo5-hvt --net:service=tap0 --net:private=tap10 --block:storage=/var/db/tlstunnel -- \
  tlstunnel/unikernel/dist/tlstunnel.hvt --ipv4=1.2.3.4/24 --ipv4-gateway=1.2.3.1 \
  --private-ipv4=192.168.0.4/24 --domains=example.org \
  --dns-server=1.2.3.5 --dns-key=tlstunnel._update.example.org:SHA256:m2gls0y3ZMN4DVKx37x/VoKEdll4J2A9qNIl6JIz2z4= \
  --key-seed=ROkD8o/Xrc4ScDdxM8cV1+4eQiWUEul+3I1twW+I15E= \
  --key=9Fe92fogykIAPBJZU4FUsmpRsAy6YDajIkdSRs650zM=
```

Now, once tlstunnel managed to get a certificate via DNS, you can already
connect to https://1.2.3.4 and should see the certificate:

```bash
$ openssl s_client -connect 1.2.3.4:443
$ curl https://1.2.3.4
```

To configure TLStunnel's forwarding, where a specified hostname will be
forwarded to an IP address and port pair, you have to use the binary
`tlstunnel-client` from the `client` subfolder. The communication is
authenticated using the shared secret passed to TLStunnel (`--key=secret`).

The configuration is kept in the block device (in a robust way, i.e. on change
first the new data is written and afterwards the superblock is updates).

```bash
$ cd tlstunnel/client
$ dune build

# Listing all configured hostnames:
$ _build/install/default/bin/tlstunnel-client list --key=9Fe92fogykIAPBJZU4FUsmpRsAy6YDajIkdSRs650zM= -r 192.168.0.4:1234

# Adding a new forward:
$ _build/install/default/bin/tlstunnel-client add --key=9Fe92fogykIAPBJZU4FUsmpRsAy6YDajIkdSRs650zM= -r 192.168.0.4:1234 test.example.org 192.168.0.42 80

# Removing a foward:
$ _build/install/default/bin/tlstunnel-client remove --key=9Fe92fogykIAPBJZU4FUsmpRsAy6YDajIkdSRs650zM= -r 192.168.0.4:1234 test.example.org
```

## Installation from source

To install this unikernel from source, you need to have
[opam](https://opam.ocaml.org) (>= 2.0.0) and
[ocaml](https://ocaml.org) (>= 4.08.0) installed. Also,
[mirage](https://mirageos.org) is required (>= 4.0.0). Please follow the
[installation instructions](https://mirageos.org/wiki/install).

The following steps will clone this git repository and compile the unikernel:

```bash
$ git clone https://github.com/robur-coop/tlstunnel.git
$ cd tlstunnel/unikernel && mirage configure -t <your-favourite-target>
$ make depend
$ mirage build
```

## Installing as binary

Binaries are available at [Reproducible OPAM
builds](https://builds.robur.coop/job/tlstunnel/), see [Deploying binary MirageOS
unikernels](https://hannes.robur.coop/Posts/Deploy) and [Reproducible MirageOS
unikernel builds](https://hannes.robur.coop/Posts/ReproducibleOPAM) for details.

## Questions?

Please open an issue if you have questions, feature requests, or comments.
