# TUIC

Delicately-TUICed 0-RTT proxy protocol

A fork of original TUIC repo https://github.com/EAimTY/tuic

Compared to origin, this fork's new features:
- In-tree [docker image builds](https://github.com/Itsusinn/tuic/pkgs/container/tuic-server)
- Up-to-date dependencies
- More relaxed locks
- More CI targets via [cross-rs](https://github.com/cross-rs/cross)
- Self-signed cert and `skip_cert_verify` support
- ServerCert auto hot-reload
- And [more...](https://github.com/EAimTY/tuic/compare/dev...Itsusinn:tuic:dev)

## Introduction

TUIC is a proxy protocol focusing on minimize the additional handshake latency caused by relaying as much as possible, as well as keeping the protocol itself being simple and easy to implement

TUIC is originally designed to be used on top of the [QUIC](https://en.wikipedia.org/wiki/QUIC) protocol, but you can use it with any other protocol, e.g. TCP, in theory

When paired with QUIC, TUIC can achieve:

- 0-RTT TCP proxying
- 0-RTT UDP proxying with NAT type [Full Cone](https://www.rfc-editor.org/rfc/rfc3489#section-5) 
- 0-RTT authentication
- Two UDP proxying modes:
    - `native`: Having characteristics of native UDP mechanism
    - `quic`: Transferring UDP packets losslessly using QUIC streams
- Fully multiplexed
- All the advantages of QUIC, including but not limited to:
    - Bidirectional user-space congestion control
    - Optional 0-RTT connection handshake
    - Connection migration

Fully-detailed TUIC protocol specification can be found in [SPEC.md](https://github.com/Itsusinn/tuic/tree/dev/tuic/SPEC.md)

## Overview

There are 4 crates provided in this repository:

- **[tuic](https://github.com/Itsusinn/tuic/tree/dev/tuic)** - Library. The protocol itself, protocol & model abstraction, synchronous / asynchronous marshalling
- **[tuic-quinn](https://github.com/Itsusinn/tuic/tree/dev/tuic-quinn)** - Library. A thin layer on top of [quinn](https://github.com/quinn-rs/quinn) to provide functions of TUIC
- **[tuic-server](https://github.com/Itsusinn/tuic/tree/dev/tuic-server)** - Binary. Minimalistic TUIC server implementation as a reference
- **[tuic-client](https://github.com/Itsusinn/tuic/tree/dev/tuic-client)** - Binary. Minimalistic TUIC client implementation as a reference

## Contribute TUIC

[Search TODO in code base](https://github.com/search?q=repo%3AItsusinn%2Ftuic%20todo&type=code) or [Assist with Open Issues](https://github.com/Itsusinn/tuic/issues?q=label%3A%22help+wanted%22+is%3Aissue+is%3Aopen)

## License

Code in this repository is licensed under [GNU General Public License v3.0](https://github.com/Itsusinn/tuic/blob/dev/LICENSE)

However, the concept of the TUIC protocol is license-free. You can implement, modify, and redistribute the protocol without any restrictions, even for commercial use
