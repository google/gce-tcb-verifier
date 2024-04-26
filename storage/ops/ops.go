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

// Package ops provides an interface and common operations on a StorageClient.
package ops

import (
	"context"
	"fmt"
	"io"

	"github.com/google/gce-tcb-verifier/storage/storagei"
)

// WriteFile writes (over) contents of object `name` in `bucket` with `contents`. Creates the file
// if it doesn't already exist.
func WriteFile(ctx context.Context, s storagei.Client, bucket, name string, contents []byte) error {
	w, err := s.Writer(ctx, bucket, name)
	if err != nil {
		return err
	}
	// The file needs its contents.
	closer := func() error {
		if err := w.Close(); err != nil {
			return fmt.Errorf("could not close file %q: %w", name, err)
		}
		return nil
	}
	n, err := w.Write(contents)
	if n != len(contents) || err != nil {
		if err := closer(); err != nil {
			return err
		}
		return fmt.Errorf("could not write file %q: %w", name, err)
	}
	return closer()
}

// ReadFile returns the file's contents or an empty array if the file doesn't exist.
func ReadFile(ctx context.Context, s storagei.Client, bucket, name string) ([]byte, error) {
	reader, err := s.Reader(ctx, bucket, name)
	if s.IsNotExists(err) {
		return nil, fmt.Errorf("file \"%s/%s\" does not exist", bucket, name)
	}
	if err != nil {
		return nil, fmt.Errorf("could not read file %q: %w", name, err)
	}
	defer reader.Close()
	return io.ReadAll(reader)
}
