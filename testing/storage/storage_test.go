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

package storage

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestReadSimple(t *testing.T) {
	ctx := context.Background()
	want := []byte(`a contents`)
	m := WithInitialContents(map[string][]byte{"a": want}, "test")

	if err := m.EnsureBucketExists(ctx, "test"); err != nil {
		t.Error(err)
	}

	r, err := m.Reader(ctx, "test", "a")
	if err != nil {
		t.Error(err)
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("simple reader static contents got %v, want %v", got, want)
	}

	if err := r.Close(); err != nil {
		t.Error(err)
	}
}

func TestReadAfterWrite(t *testing.T) {
	ctx := context.Background()
	want := []byte(`a contents`)
	m := WithInitialContents(nil, "test")
	w, err := m.Writer(ctx, "test", "a")
	if err != nil {
		t.Error(err)
	}
	if _, err := w.Write(want); err != nil {
		t.Errorf("writer.Write(%v) = %v, want nil", want, err)
	}
	if err := w.Close(); err != nil {
		t.Error(err)
	}
	r, err := m.Reader(ctx, "test", "a")
	if err != nil {
		t.Error(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("read after write got %v, want %v", got, want)
	}
	if err := r.Close(); err != nil {
		t.Error(err)
	}
}

func TestReadAfterWriteOfStatic(t *testing.T) {
	ctx := context.Background()
	want := []byte(`a contents`)
	m := WithInitialContents(map[string][]byte{"a": []byte(`previous`)}, "test")
	w, err := m.Writer(ctx, "test", "a")
	if err != nil {
		t.Error(err)
	}
	if _, err := w.Write(want); err != nil {
		t.Errorf("writer.Write(%v) = %v, want nil", want, err)
	}
	if err := w.Close(); err != nil {
		t.Error(err)
	}
	r, err := m.Reader(ctx, "test", "a")
	if err != nil {
		t.Error(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("read after write got %v, want %v", got, want)
	}
	if err := r.Close(); err != nil {
		t.Error(err)
	}
}
