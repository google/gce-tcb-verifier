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

// Package testing provides helpers for testing gcetcbendorsement.
package testing

import (
	"fmt"
	"io"
	"os"
	"testing"

	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"google.golang.org/protobuf/proto"
)

// FailWriter is a writer that always returns an error.
type FailWriter struct{}

// Write implements the Writer interface's Write method and returns an error.
func (FailWriter) Write(b []byte) (int, error) { return 0, fmt.Errorf("nope") }

// GoldenT returns a serialized VMGoldenMeasurement while reporting errors to the test interface.
func GoldenT(t testing.TB, g *epb.VMGoldenMeasurement) []byte {
	out, err := proto.Marshal(g)
	if err != nil {
		t.Fatalf("proto.Marshal(%v) = %v, want nil", g, err)
	}
	return out
}

type closeOnRead struct {
	r *os.File
	w *os.File
}

func (r *closeOnRead) Close() error { return r.r.Close() }
func (r *closeOnRead) Read(b []byte) (int, error) {
	if r.w != nil {
		if err := r.w.Close(); err != nil {
			return 0, err
		}
		r.w = nil
	}
	return r.r.Read(b)
}

// Pipe returns a pipe that closes the writer on first read.
func Pipe() (io.ReadCloser, *os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	return &closeOnRead{r: r, w: w}, w, nil
}
