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

package ovmf

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIntersect(t *testing.T) {
	tcs := []struct {
		name  string
		left  GuestPhysicalRegion
		right GuestPhysicalRegion
		want  GuestPhysicalRegion
	}{
		{
			name:  "non-overlapping left < right",
			left:  GuestPhysicalRegion{Start: 0, Length: 10},
			right: GuestPhysicalRegion{Start: 10, Length: 10},
			want:  GuestPhysicalRegion{},
		},
		{
			name:  "non-overlapping right < left",
			left:  GuestPhysicalRegion{Start: 10, Length: 10},
			right: GuestPhysicalRegion{Start: 0, Length: 10},
			want:  GuestPhysicalRegion{},
		},
		{
			name:  "overlapping left < right",
			left:  GuestPhysicalRegion{Start: 0, Length: 11},
			right: GuestPhysicalRegion{Start: 10, Length: 10},
			want:  GuestPhysicalRegion{Start: 10, Length: 1},
		},
		{
			name:  "overlapping right < left",
			left:  GuestPhysicalRegion{Start: 10, Length: 10},
			right: GuestPhysicalRegion{Start: 0, Length: 11},
			want:  GuestPhysicalRegion{Start: 10, Length: 1},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.left.intersect(tc.right)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("%v.intersect(%v) returned diff (-want +got):\n%s", tc.left, tc.right, diff)
			}
		})
	}
}
