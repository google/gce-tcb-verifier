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

// The gendata tool outputs the CleanExample measurements as a hex string
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/tdx"
	"github.com/google/gce-tcb-verifier/testing/fakeovmf"
	sgpb "github.com/google/go-sev-guest/proto/sevsnp"
)

func cleanSnp(fw []byte) {
	meas, err := sev.LaunchDigest(&sev.LaunchOptions{Vcpus: 1, Product: sgpb.SevProduct_SEV_PRODUCT_MILAN}, fw)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(meas))
}

func cleanTdx(fw []byte) {
	meas, err := tdx.MRTD(tdx.LaunchOptionsDefault("c3-standard-4"), fw)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(meas[:]))
}

func main() {
	t := &testing.T{}
	fw := fakeovmf.CleanExample(t, 2*1024*1024)
	fmt.Print("SEV-SNP\t")
	cleanSnp(fw)
	fmt.Print("TDX\t")
	cleanTdx(fw)
}
