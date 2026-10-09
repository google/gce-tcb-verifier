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

package timeproto

import (
	"testing"
	"time"
)

func TestFromNilDoesNotPanic(t *testing.T) {
	if got := From(nil); !got.IsZero() {
		t.Errorf("From(nil) = %v, want zero Time", got)
	}
}

func TestFromToRoundTrip(t *testing.T) {
	want := time.Unix(1700000000, 12345)
	if got := From(To(want)); !got.Equal(want) {
		t.Errorf("From(To(%v)) = %v, want %v", want, got, want)
	}
}
