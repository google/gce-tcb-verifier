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
	"testing"
)

func TestVerifyCert(t *testing.T) {
	want := `openssl verify -CAfile <(openssl x509 -outform pem -in <(curl https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt)) \
  <(gcetcbendorsement inspect mask "FILE.binarypb" --path=cert)`
	if got := OpensslVerifyCertShellCmd("gcetcbendorsement", "FILE.binarypb", DefaultRootCmd); got != want {
		t.Errorf("OpensslVerifyCert(%q, %q) = %q, want %q", "gcetcbendorsement", "FILE.binarypb", got, want)
	}
}

func TestVerify(t *testing.T) {
	want := `openssl pkeyutl -verify -pkeyopt rsa_padding_mode:pss \
  -pkeyopt rsa_pss_saltlen:32 -pkeyopt digest:sha256 -pkeyopt rsa_mgf1_md:sha256 -pubin \
  -inkey <(openssl x509 -pubkey -nocert -outform pem -in <(gcetcbendorsement inspect mask "FILE.binarypb" --path=cert)) \
  -sigfile <(gcetcbendorsement inspect signature "FILE.binarypb") -keyform PEM \
  -in <(openssl dgst -sha256 -binary <(gcetcbendorsement inspect payload "FILE.binarypb"))`
	if got := OpensslVerifyShellCmd("gcetcbendorsement", "FILE.binarypb"); got != want {
		t.Errorf("OpensslVerify(%q, %q) = %q, want %q", "gcetcbendorsement", "FILE.binarypb", got, want)
	}
}
