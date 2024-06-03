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

// Package extracttdx contains the implementation of the endorsement location derivation from MRTD.
package extracttdx

import (
	"encoding/hex"
	"fmt"
)

// gceTcbObjectPath returns the object path within the gce_tcb_integrity GCS bucket that
// corresponds to the given SEV-SNP attestation report measurement.
func gceTcbObjectPath(measurement []byte) string {
	return fmt.Sprintf("tdx/%s.binarypb", hex.EncodeToString(measurement))
}

// GCETcbObjectName returns the expected object name within a GCS bucket for a firmware
// measured for TDX.
func GCETcbObjectName(measurement []byte) string {
	return fmt.Sprintf("ovmf_x64_csm/%s", gceTcbObjectPath(measurement))
}
