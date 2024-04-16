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

// Package storagei provides a storage interface type that can be used for file management.
package storagei

import (
	"golang.org/x/net/context"
	"io"
)

// Client defines the necessary slice needed for interacting with storage.
type Client interface {
	Reader(ctx context.Context, bucket, object string) (io.ReadCloser, error)
	Exists(ctx context.Context, bucket, object string) (bool, error)
	Writer(ctx context.Context, bucket, object string) (io.WriteCloser, error)
	IsNotExists(err error) bool
	EnsureBucketExists(ctx context.Context, bucket string) error
	Wipeout(ctx context.Context, bucket string) error
}
