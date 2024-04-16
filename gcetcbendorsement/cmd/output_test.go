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

package cmd

import (
	"path"
	"testing"
)

func TestOSIO(t *testing.T) {
	// Appease the coverage metrics.
	i := OSIO{}
	dir := t.TempDir()
	p := path.Join(dir, "test.txt")
	w, cleanup, err := i.Create(p)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	w.Write([]byte("hello"))
	cleanup()
	got, err := i.ReadFile(p)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("ReadFile(%q) = %q, want %q", p, string(got), "hello")
	}
}
