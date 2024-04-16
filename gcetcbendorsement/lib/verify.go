// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcetcbendorsement

import (
	"fmt"
)

const (
	// DefaultRootURL is the trusted location of the GCE Confidential Computing TCB signing key root
	// certificate.
	DefaultRootURL = "https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt"
	// DefaultRootCmd is a shell command for use as a path to the root certificate.
	DefaultRootCmd = "<(curl " + DefaultRootURL + ")"
)

// OpensslVerifyCertShellCmd returns the shell command for using openssl to verify the code-
// signing certificate inside the endorsement in path `endorsement` as extracted by the
// gcetcbendorsement CLI tool at the `self` path. The `endorsement` path must be to a file
// containing a binary-serialized VMLaunchEndorsement.
func OpensslVerifyCertShellCmd(self, endorsement, root string) string {
	// The root may be a DER or PEM format file.
	return fmt.Sprintf(`openssl verify -CAfile <(openssl x509 -outform pem -in %s) \
  <(%s inspect mask %q --path=cert)`, root, self, endorsement)
}

// OpensslVerifyShellCmd returns the shell command for using openssl and the gcetcbendorsement
// CLI tool at path `self` to verify the endorsement at path `endorsement` signature. The
// `endorsement` path must be to a file containing a binary-serialized VMLaunchEndorsement.
func OpensslVerifyShellCmd(self, endorsement string) string {
	return fmt.Sprintf(`openssl pkeyutl -verify -pkeyopt rsa_padding_mode:pss \
  -pkeyopt rsa_pss_saltlen:32 -pkeyopt digest:sha256 -pkeyopt rsa_mgf1_md:sha256 -pubin \
  -inkey <(openssl x509 -pubkey -nocert -outform pem -in <(%s inspect mask %q --path=cert)) \
  -sigfile <(%s inspect signature %q) -keyform PEM \
  -in <(openssl dgst -sha256 -binary <(%s inspect payload %q))`,
		self, endorsement, self, endorsement, self, endorsement)
}
