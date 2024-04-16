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

// Package localnonvcs implements the endorse.VersionControl interface without operating with an
// actual version-control system. Instead it just writes files to local disk.
package localnonvcs

import (
	"fmt"
	"golang.org/x/net/context"
	"os"
	"path"

	"github.com/google/gce-tcb-verifier/endorse"
	"github.com/spf13/cobra"
)

// T implements endorse.VersionControl without version control. It simply allows writing files to
// local disk.
type T struct {
	Root string
}

// changeOps implements endorse.ChangeOps
type changeOps struct{}

// WriteOrCreateFiles creates or overwrites all given files with their paired contents, or returns
// an error.
func (*changeOps) WriteOrCreateFiles(ctx context.Context, files ...*endorse.File) error {
	for _, f := range files {
		parent := path.Dir(f.Path)
		if err := os.MkdirAll(parent, 0755); err != nil {
			return fmt.Errorf("localnonvcs could not create directory %q: %v", parent, err)
		}
		if err := os.WriteFile(f.Path, f.Contents, 0755); err != nil {
			return fmt.Errorf("localnonvcs could not write file %q: %v", f.Path, err)
		}
	}
	return nil
}

// ReadFile returns the content of the given file, or an error.
func (*changeOps) ReadFile(ctx context.Context, path string) ([]byte, error) {
	return os.ReadFile(path)
}

// SetBinaryWritable sets the metadata of the given file to denote it as binary and writable, and
// returns nil on success.
func (*changeOps) SetBinaryWritable(ctx context.Context, path string) error {
	return os.Chmod(path, 0755)
}

// IsNotFound returns if any errors returned by the implementation should be interpreted as file
// not found.
func (*changeOps) IsNotFound(err error) bool {
	return os.IsNotExist(err)
}

// Destroy reclaims any resources this object is using.
func (*changeOps) Destroy() {}

// TryCommit returns a representation of the successful commit or an error.
func (*changeOps) TryCommit(ctx context.Context) (any, error) {
	return nil, nil
}

// GetChangeOps returns a filesystem abstraction within the context of a commit attempt.
func (*T) GetChangeOps(ctx context.Context) (endorse.ChangeOps, error) {
	return &changeOps{}, nil
}

// RetriableError returns true if TryCommit's provided error is retriable.
func (*T) RetriableError(err error) bool { return false }

// Result returns a successful commit's representation given a successful TryCommit's result and
// the path to the created endorsement.
func (*T) Result(commit any, endorsementPath string) any { return nil }

// ReleasePath translates a path to its expected full path for WriteOrCreateFiles/ReadFile.
func (t *T) ReleasePath(ctx context.Context, certPath string) string {
	return path.Join(t.Root, certPath)
}

// T is also a command component

// InitContext extends the given context with whatever else the component needs before execution.
func (t *T) InitContext(ctx context.Context) (context.Context, error) {
	ec, err := endorse.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	ec.VCS = t
	return ctx, nil
}

// AddFlags adds any implementation-specific flags for this command component.
func (t *T) AddFlags(c *cobra.Command) {
	c.PersistentFlags().StringVar(&t.Root, "out_root", "",
		"The local filesystem root in which to interpret the relative --out_dir path.")
}

// PersistentPreRunE returns an error if the results of the parsed flags constitute an error.
func (t *T) PersistentPreRunE(cmd *cobra.Command, args []string) error {
	if t.Root == "" {
		return nil
	}
	s, err := os.Stat(t.Root)
	if err != nil {
		return fmt.Errorf("could net stat --out_root=%q: %v", t.Root, err)
	}
	if !s.IsDir() {
		return fmt.Errorf("--out_root=%q is not a directory", t.Root)
	}
	return nil
}
