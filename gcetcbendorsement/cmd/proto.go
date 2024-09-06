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
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"
)

// ReadProto reads a binary proto from path using the context's backend IO object, and
// unmarshals it into m.
func ReadProto(ctx context.Context, path string, m proto.Message) error {
	backend, err := backendFrom(ctx)
	if err != nil {
		return err
	}
	content, err := backend.IO.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file %q: %v", path, err)
	}
	if err := proto.Unmarshal(content, m); err != nil {
		return fmt.Errorf("failed to unmarshal proto %T file %q: %v", m, path, err)
	}
	return nil
}
