# gce-tcb-verifier

This project provides tools for creating and verifying launch endorsements for
binaries included in Google Compute Engine Confidential Virtual Machines at
launch.

Of particular note in these libraries is the derivation of Open Virtual Machine
Firmware (OVMF) binaries to their expected SEV-SNP measurement.

## Terms

A "launch endorsement" is a signed "golden measurement". Each trusted execution
environment technology has its own process for measuring the initial state of a
virtual machine. The final result is called the "measurement", and is included
in the technology's remote attestation report.

The launch endorsement is provided as a binary-serialized `VMLaunchEndorsement`
message from `proto/endorsement.proto`.

## Transparency

The OVMF SHA-384 digest in a golden measurement binds the launch endorsement to
a specific build of the firmware. Google publishes its production virtual
firmware binaries for transparency. Verifying parties may download the 2MiB
image to inspect and reproduce the golden measurement from.

The root certificate(s) for code signatures are available at

https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt

The `_1` naming convention is to allow for root rotation if required, with an
increase to `_2`, etc. Such an event will come with advance notice.

We recommend to fetch this certificate yourself to establish trust through the
HTTPS certificate, as it links itself to Google.

## Inspecting endorsements

The `VMLaunchEndorsement` serialized binary that asserts authenticity of a
firmware binary needs some help to be more human-digestible. The
[`gcbtcbendorsement` CLI tool](gcetcbendorsement/README.md) provides commands
for extracting information from an endorsement binary.

## Verifying endorsements

The `verify` library includes the protocol buffer deserialization and signature
verification logic that the simple format requires. Since the endorsement
document is provided from the host certificate cache and needs to be compared
against an attestation report's measurement, the `verify` library composes with
`go-sev-guest`'s verification options to fully validate a GCE attestation report
via `verify.SNPValidateFunc`.

The `gcetcbendorsement` CLI tool provides commands that expose this behavior in
a binary.

## Non-production endorsement

Whereas genuine firmware binaries are signed by access-restricted Cloud KMS
keys, the `cmd/nonprod` tool provides a locally-managed offline
certificate authority and code-signing mechanism. The default certificates
contain Google metadata, but a `keys.ManagerInterface` implementation can
provide its own certificate template. The `endorse` command will use keys in
`--key_dir` and their certificates in `--bucket_root` to sign a firmware
provided from `--uefi`.

Initial keys may be bootstrapped with the `bootstrap` command, and signing keys
can be rotated with the `rotate` command.

## AMD SEV-SNP

AMD SEV-SNP documents its measurement methodology in its SEV-SNP ABI
specification for `SNP_LAUNCH_UPDATE`. Google does not populate and authenticate
an IDBLOCK as a method of tying expected values to an attestation report since
it is not extensible. The data that would go in an IDBLOCK are provided in a
`VMSevSnp` message.

## Links

*   [AMD documentation hub](https://www.amd.com/en/search/documentation/hub.html)
*   [AMD SEV-SNP ABI specification Rev 1.55](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf)
*   [go-sev-guest](https://github.com/google/go-sev-guest)
*   [go-tdx-guest](https://github.com/google/go-tdx-guest)
*   [go-tpm-tools](https://github.com/google/go-tpm-tools)

## Disclaimers

This is not an officially supported Google product.
