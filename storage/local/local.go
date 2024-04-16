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

// Package local provides a StorageClient interface implementation for local disk file management.
package local

import (
	"fmt"
	"golang.org/x/net/context"
	"io"
	"os"
	"path"

	"github.com/google/gce-tcb-verifier/cmd/output"
)

const defaultPerm os.FileMode = 0777

// StorageClient provides the storage/ops.StorageClient interface on local disk. A bucket is a
// root directory in which relative paths are defined. Unlike a GCS storage client, the local
// StorageClient can accept a bucket of "." for current-working-directory-relative paths.
type StorageClient struct {
	Root string
}

func (s *StorageClient) localPath(bucket, object string) string {
	return path.Join(s.Root, bucket, object)
}

// Reader returns an open ReadCloser object for reading the given object.
func (s *StorageClient) Reader(_ context.Context, bucket, object string) (io.ReadCloser, error) {
	r, err := os.OpenFile(s.localPath(bucket, object), os.O_RDONLY, defaultPerm)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Writer returns an open WriteCloser object for populating the given object.
func (s *StorageClient) Writer(ctx context.Context, bucket, object string) (io.WriteCloser, error) {
	// objects in GCS can have slashes in them without needing extra mkdir commands since there's no
	// notion of a directory in GCS. We need to be more careful on a local filesystem.
	p := s.localPath(bucket, object)
	dir, _ := path.Split(p)
	if dir != "" {
		if err := os.MkdirAll(path.Join(s.Root, bucket), os.ModePerm); err != nil {
			return nil, fmt.Errorf("could not create bucket %s: %w", bucket, err)
		}
		if err := os.MkdirAll(dir, defaultPerm); err != nil {
			return nil, fmt.Errorf("could not prepare directory for object %s in bucket %s: %w", object, bucket, err)
		}
	}
	w, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, defaultPerm)
	if err != nil {
		return nil, err
	}
	output.Debugf(ctx, "opened writer for %s", p)
	return w, nil
}

// Exists returns whether a particular object exists in the given bucket, or an error.
func (s *StorageClient) Exists(ctx context.Context, bucket, object string) (bool, error) {
	_, err := os.Stat(s.localPath(bucket, object))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// IsNotExists returns whether an error from Client indicates the object in question does
// not exist.
func (s *StorageClient) IsNotExists(err error) bool {
	return os.IsNotExist(err)
}

// EnsureBucketExists creates the given bucket if it does not exist. Only the owner has privileges.
func (s *StorageClient) EnsureBucketExists(ctx context.Context, bucket string) error {
	return os.MkdirAll(path.Join(s.Root, bucket), defaultPerm)
}

// Wipeout deletes all objects in the given bucket (subdirectory)
func (s *StorageClient) Wipeout(ctx context.Context, bucket string) error {
	p := path.Join(s.Root, bucket)
	if p == "" {
		return fmt.Errorf("cannot delete current working directory")
	}
	return os.RemoveAll(p + "/")
}
