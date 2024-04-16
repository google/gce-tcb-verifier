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
	"os"

	"github.com/google/gce-tcb-verifier/gcetcbendorsement/lib/gcetcbendorsement"
)

// IO provides the functionality to produce output as commands.
type IO interface {
	// Create creates or opens and truncates a file at the given path, or returns an error. The
	// writer comes with a cleanup function instead of being a WriteCloser to allow for the created
	// writer to not close if needed.
	Create(path string) (gcetcbendorsement.TerminalWriter, func(), error)
	// ReadFile reads the entire contents of a file at the given path, or returns an error.
	ReadFile(path string) ([]byte, error)
}

// OSIO implements the IO interface with the os library.
type OSIO struct{}

// Create truncates an existing file at the given path, or creates a new file. If successful,
// returns a writer to the file and a cleanup function for the writer. Otherwise returns an error.
func (OSIO) Create(path string) (gcetcbendorsement.TerminalWriter, func(), error) {
	if path == "-" {
		return gcetcbendorsement.OSFileWriter{File: os.Stdout}, func() {}, nil
	}
	w, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return gcetcbendorsement.OSFileWriter{File: w}, func() { w.Close() }, nil
}

// ReadFile reads the entire contents of a file at the given path, or returns an error.
func (OSIO) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
