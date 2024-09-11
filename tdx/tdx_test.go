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

package tdx

import (
	"testing"

	"github.com/google/gce-tcb-verifier/ovmf"
	"github.com/google/go-cmp/cmp"
)

func TestNumaBanks(t *testing.T) {
	got := regionsForShape(shapeDesc["c3-standard-176"])
	want := []ovmf.GuestPhysicalRegion{
		{Start: 0, Length: 0xc0000000},
		{Start: 0xffe00000, Length: 0x200000},
		{Start: 0x100000000, Length: 0x2b40000000},
		{Start: 0x2c40000000, Length: 0x2c00000000},
		{Start: 0x5840000000, Length: 0x2c00000000},
		{Start: 0x8440000000, Length: 0x2c00000000},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("RAM banks for c3-standard-176 is not as expected: %s", diff)
	}
}
