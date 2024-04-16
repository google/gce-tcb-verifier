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

// Package timeproto provides functions for translating timestamps between Golang and Protobuf.
package timeproto

import (
	"time"

	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

// To translates a golang Time object to a protobuf Timestamp message.
func To(t time.Time) *tspb.Timestamp {
	const NanosPerSecond = 1000000000
	return &tspb.Timestamp{
		Seconds: t.Unix(),
		Nanos:   int32(t.UnixNano() % NanosPerSecond),
	}
}

// From translates a protobuf Timestamp message to a Golang Time object.
func From(t *tspb.Timestamp) time.Time {
	return time.Unix(t.Seconds, int64(t.Nanos))
}
