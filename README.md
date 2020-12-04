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

## Installation from source

To install this unikernel from source, you need to have
[opam](https://opam.ocaml.org) (>= 2.0.0) and
[ocaml](https://ocaml.org) (>= 4.07.0) installed. Also,
[mirage](https://mirageos.org) is required (>= 3.10.0). Please follow the
[installation instructions](https://mirageos.org/wiki/install).

The following steps will clone this git repository and compile the unikernel:

```bash
$ git clone https://github.com/roburio/tlstunnel.git
$ mirage configure -t <your-favourite-target>
$ make depend
$ make
```

## Installing as binary

There are not yet any binaries available, but work is underway to provide
reproducible binaries.

## Questions?

Please open an issue if you have questions, feature requests, or comments.
