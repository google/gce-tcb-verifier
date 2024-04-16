# `gcbtcbendorsement` CLI tool

Endorsements produced by the CLI tool in `cmd/nonprod` can be interpreted with
this tool. The output is in the form of a binary-serialized
`VMLaunchEndorsement` defined in
[proto/endorsement.proto](../proto/endorsement.proto), which for now is only
used for providing measurements of the Open Virtual Machine Firmware (OVMF) UEFI
implementation.

This tool provides commands for fetching and interpreting the UEFI endorsement.

## What is endorsed

A `VMLaunchEndorsement` contains signed reference values to compare with trusted
execution environment (TEE) attestation reports (AKA quotes) that include a
measurement of the machine state at power-on. For GCE VMs this is includes the
firmware ROM, vCPU state, and TEE-specific configuration options.

An endorsement file contains the binary serialization of the
`VMLaunchEndorsement` message that the firmware vendor created offline prior to
the firmware deployment. It is a pair of bytes that were signed, and the
signature itself. The signing key's certificate is contained within the signed
bytes, but the certificate's signature comes from
[the root key](https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt).

The signed bytes themselves are another serialized protocol buffer,
`VMGoldenMeasurement`. This includes the timestamp the endorsement was created,
very basic provenance information, and further information about the firmware
and TEE-specifics.

```
message VMGoldenMeasurement {
  google.protobuf.Timestamp timestamp = 1;

  // The changelist number this UEFI was built from.
  uint64 cl_spec = 2;

  // The commit hash this UEFI was built from.
  bytes commit = 3;

  // DER format certificate of the key that signed this document.
  bytes cert = 4;

  // SHA-384 digest of the UEFI binary without TEE-specifics about launch.
  bytes digest = 5;

  // A sequence of PEM-encoded certificates of keys used in cert in Root ...
  // final intermediate order. The last certificate will have signed cert.
  bytes ca_bundle = 6;

  VMSevSnp sev_snp = 7;
}
```

The `commit` and `ca_bundle` fields are currently unused.

### SEV-SNP specifics

Google Compute Engine does not use the IDBLOCK structure for SEV-SNP VM launch
endorsement. Instead the fields that would be included there are in the
`VMSevSnp` message.

```
message VMSevSnp {
  // The Google-reported security version number of this UEFI on SEV-SNP.
  uint32 svn = 1;
  // Expected MEASUREMENT report field values given [key]-many VMSAs at launch.
  map<uint32, bytes> measurements = 2;  // bytes size 48
  // A UUID that Google uses for its CVM UEFIs
  bytes family_id = 3;  // size 16
  // A UUID to name this specific release of the UEFI image.
  bytes image_id = 4;  // size 16
  // The launch policy that verifiers should expect with this UEFI.
  uint64 policy = 5;
  // Optional. PEM-encoded certs for Identity..Author..Root. If a singleton,
  // only an Id-key is used.
  bytes ca_bundle = 6;
}
```

The `family_id` and `image_id` fields are for attestation verifiers to
interpret, but the corresponding fields of the SEV-SNP attestation report
should be expected to be zeros.

The launch policy for SEV-SNP VMs (AKA guest policy) is not user-configurable on
Google Compute Engine and should always match the reference value.

## Common uses

### Check the authenticity of the endorsement file

```shell
gcetcbendorsement verify "${ENDORSEMENT_PATH?}"
```

### Extract the endorsement for the VM you're running on

Every firmware measurement possible on Google Compute Engine should be accounted
for with an endorsed measurement, so a user in a TEE with permissions to get an
attestation report can run the following to get a local or remote copy of the
endorsement for the firmware the VM is running.

```shell
gcetcbendorsement extract --out="${ENDORSEMENT_PATH?}"
```

### Extract the endorsement from a GCE VM attestation report

If not on the node itself, the measurement itself is enough to identify a copy
of the firmware's endorsement in Google Cloud Storage.

```shell
gcetcbendorsement extract "${ATTESTATION_PATH?}" --out="${ENDORSEMENT_PATH?}"
```

### Check an attestation report against an endorsement

You may want to augment your own attestation report appraisal logic to check
the signed firmware measurement.

```shell
gcetcbendorsement sev validate "${ATTESTATION_PATH?}" \
  --endorsement="${ENDORSEMENT_PATH?}" \
  --allow_unspecified_vmsas
```

## Commands

*   `extract`: Outputs the endorsement from an input attestation, or attempts to
    download it if unavailable.
*   `inspect`: offers options to output the contents of specific fields of the
    endorsement, such as the payload that is signed, the (encoded) signature,
    and fields of the payload when decoded as a `VMGoldenMeasurement`.
*   `verify`: checks cryptographic signatures. The first is the root key's
    signature of the signing key's certificate and the second is the signing
    key's signature of the serialized `VMGoldenMeasurement`.
*   `sev`: offers options for amending a base
    [go-sev-guest](https://github.com/google/go-sev-guest) checking policy with
    an endorsement's reference values and simply checking an endorsement against
    an attestation and optional base policy.

### `extract`

```
gcetcbendorsement extract [FILE] [--out=FILE]
```

Reads the given file as any of the output formats of go-sev-guest’s attest tool,
a go-tpm-tools attestation, or the contents of the `auxblob` attribute from
`configfs-tsm` and outputs the embedded UEFI endorsement to the given path.
Default is `--out=endorsement.binarypb` since the contents aren't easily
human-readable in any form.

If no input file is given, it expects to be running as a guest and attempts to
get the certificate locally from an extended report, and then attempts via
network.

### `inspect`

```
gcetcbendorsement inspect CMD FILE [options]
```

Options for all inspect commands:

*   `--out=FILE`: where to write the output. Default is stdout, i.e., `--out=-`.
*   `--bytesform=bin|hex|base64|auto`: selects whether bytes fields should be
    output as raw binary, or encoded as hex or base64. Default is `auto`, which
    chooses base64 for terminal outputs and binary otherwise.

`CMD` specifies what part of the endorsement to inspect:

*   `signature`: outputs the signature bytes.
*   `payload`: outputs the serialized `VMGoldenMeasurement` bytes.
*   `mask`: outputs the fields of the `VMGoldenMeasurement` selected by the
    paths in the repeatable flag `--path`, e.g., `--path=timestamp`,
    `--path=sev_snp.svn`, or `--path=sev_snp.measurements[8]`.

### `verify`

```
gcetcbendorsement verify FILE [--show|--root_cert=FILE]
```

Checks cryptographic signatures. The first is the root key's signature of the
signing key's certificate and the second is the signing key's signature of the
serialized `VMGoldenMeasurement`.

If run with `--show`, outputs a shell command that uses Openssl which is
equivalent to running the command without `--show`:

```shell
$ gcetcbendorsement verify FILE --show
openssl dgst -verify <(gcetcbendorsement inspect mask FILE --path=cert) \
 -signature <(gcetcbendorsement inspect signature FILE) \
 <(gcetcbendorsement inspect payload FILE)
&&
openssl verify -CAfile <(curl https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt) \
  -untrusted <(gcetcbendorsement inspect mask FILE --path=cert)
```

and

```shell
$ gcetcbendorsement verify FILE --show --root_cert=root.crt
openssl dgst -verify <(gcetcbendorsement inspect mask FILE --path=cert) \
 -signature <(gcetcbendorsement inspect signature FILE) \
 <(gcetcbendorsement inspect payload FILE)
&&
openssl verify -CAfile root.crt \
  -untrusted <(gcetcbendorsement inspect mask FILE --path=cert)
```

The shell command can therefore be run directly with

```shell
$ $(gcetcbendorsement verify FILE --show)
```

Without `--show`, `gcetcbendorsement verify FILE` returns the functional
equivalent of running the openssl commands, but with the Golang crypto library.
On success, the command will return a 0 exit code. On failure, it will log an
error message and exit with a non-zero exit code.

### `sev`

```
gcetcbendorsement sev CMD FILE [options]
```

Options for both sev subcommands:

*   `--overwrite`: If `--overwrite=false` or `--nooverwrite`, it is an error for
    populated base policy fields to be overwritten. Default is false.
*   `--base=FILE`: Path to base
    [go-sev-guest check.Policy](https://github.com/google/go-sev-guest/tree/main/proto/check.proto).
    Default is `""`, equivalent to `&Policy{Policy: 0x70000, MinimumVersion:
    "0.0"}`
*   `--launch_vmsas=#`: Number of VMSAs measured at launch. This should be the
    number of vCPUs the VM was created with. If running with an SVSM, it should
    be 1. Default 0 for unspecified, which is an error without
    `--allow_unspecified_vmsas`.
*   `--allow_unspecified_vmsas`: If true, then commands will not error when
    `--launch_vmsas=0`. See individual commands for the impact on behavior.
    Default false.

#### `policy` subcommand:

Produces a
[`check.Policy`](https://github.com/google/go-sev-guest/tree/main/proto/check.proto)
with reference values from an endorsement. It may amend an optional `--base`
policy. If fields conflict, the command will fail unless `overwrite` is true.
If `--launch_vmsas=0` and `--allow_unspecified_vmsas`, then the base policy's
measurement field will not be changed.

The `FILE` mandatory argument is expected to be a binary-serialized
`VMLaunchEndorsement`.

Options:

*   `--out=FILE`: A path to the output location for the updated policy. Default
    is stdout, i.e., `-out=-`.
*   `--outform=textproto|bin|hex|base64|auto`: selects the output format of the
    policy. Use `textproto` for human-readable format or one of `bin`, `hex`,
    `base64`, or `auto` (default). If `auto` and the output is a terminal, the
    output format is `textproto`, otherwise `bin`. The `bin`, `hex`, and
    `base64` output forms are raw or encoded forms of the serialized binary
    protocol buffer.

#### `validate` subcommand:

Returns the results of comparing endorsed values (and optional base policy)
against an attestation report. If `--launch_vmsas=0` and
`--allow_unspecified_vmsas`, then an attestation is valid only if its
measurement is in the endorsement for any number of VMSAs.

The `FILE` mandatory argument is expected to be an attestation report (and
optional collateral) in one of the supported formats.

Options:

*   `--endorsement=FILE`: A path to a binary serialized `VMLaunchEndorsement` to
    supplement or replace the endorsement collateral of the attestation report.
    Default `""` and will **not** attempt to extract an endorsement from the
    local environment as with `extract`.
*   `--root_cert=FILE`: A path to the endorsement root signing certificate. If
    empty, defaults to attempting to download the `GCE-cc-tcb-root_1.crt` root
    certificate from `pki.goog`.

Returns exit code 0 if all fields of the given attestation pass go-sev-guest
validation against the given endorsement.
