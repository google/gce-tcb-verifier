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

// Package match provides utilities for tests to check if results match expectations.
package match

import (
	"strings"
)

// Error returns true iff a given error matches an expected error message. An empty message
// is interpreted as the expectation that err is nil.
func Error(err error, wantErr string) bool {
	if err == nil {
		return wantErr == ""
	}
	// An error should have an expected error message.
	// Contains is trivially true for empty strings, but empty means no error, so check that too.
	return wantErr != "" && strings.Contains(err.Error(), wantErr)
}
