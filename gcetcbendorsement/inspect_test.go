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

package gcetcbendorsement

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	testlib "github.com/google/gce-tcb-verifier/gcetcbendorsement/testing"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/gce-tcb-verifier/testing/match"
	fmpb "google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestContext(t *testing.T) {
	if err := InspectPayload(context.Background(), nil); err != ErrNoInspect {
		t.Fatalf("InspectPayload(bg, nil) = %v. Want %v", err, ErrNoInspect)
	}
}

func TestInspectPayload(t *testing.T) {
	ctx0 := context.Background()
	tcs := []struct {
		name    string
		inspect *Inspect
		rw      func() (io.Reader, TerminalWriter, func())
		want    []byte
		wantErr string
	}{
		{
			name:    "happy path",
			inspect: &Inspect{Form: BytesRaw},
			rw: func() (io.Reader, TerminalWriter, func()) {
				b := bytes.NewBufferString("")
				return b, NonterminalWriter{b}, func() {}
			},
			want: []byte{5, 1, 4},
		},
		{
			name:    "happy stdio",
			inspect: &Inspect{Form: BytesHex},
			rw: func() (io.Reader, TerminalWriter, func()) {
				oldStdout := os.Stdout
				r, w, err := testlib.Pipe()
				os.Stdout = w
				if err != nil {
					t.Fatalf("testlib.Pipe() = _, _, %v errored unexpectedly", err)
				}
				return r, nil, func() { os.Stdout = oldStdout }
			},
			want: []byte("050104"),
		},
		{
			name:    "bad write",
			inspect: &Inspect{Form: BytesRaw},
			rw: func() (io.Reader, TerminalWriter, func()) {
				return nil, NonterminalWriter{testlib.FailWriter{}}, func() {}
			},
			wantErr: "nope",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			r, w, deffn := tc.rw()
			defer deffn()
			tc.inspect.Writer = w
			if err := InspectPayload(WithInspect(ctx0, tc.inspect), &epb.VMLaunchEndorsement{
				SerializedUefiGolden: []byte{5, 1, 4},
			}); !match.Error(err, tc.wantErr) {
				t.Fatalf("InspectPayload() = %v errored unexpectedly. Want %q", err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("io.ReadAll(r) = %v errored unexpectedly", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("InspectPayload({..%v}, _) wrote %v, want %v", tc.inspect, got, tc.want)
			}
		})
	}
}

func TestInspectSignature(t *testing.T) {
	ctx0 := context.Background()
	tcs := []struct {
		name    string
		inspect *Inspect
		rw      func() (io.Reader, TerminalWriter, func())
		want    []byte
		wantErr string
	}{
		{
			name:    "happy path",
			inspect: &Inspect{Form: BytesRaw},
			rw: func() (io.Reader, TerminalWriter, func()) {
				b := bytes.NewBufferString("")
				return b, NonterminalWriter{b}, func() {}
			},
			want: []byte{5, 1, 4},
		},
		{
			name:    "happy stdio",
			inspect: &Inspect{Form: BytesHex},
			rw: func() (io.Reader, TerminalWriter, func()) {
				oldStdout := os.Stdout
				r, w, err := testlib.Pipe()
				os.Stdout = w
				if err != nil {
					t.Fatalf("testlib.Pipe() = %v errored unexpectedly", err)
				}
				return r, nil, func() { os.Stdout = oldStdout }
			},
			want: []byte("050104"),
		},
		{
			name:    "bad write",
			inspect: &Inspect{Form: BytesRaw},
			rw: func() (io.Reader, TerminalWriter, func()) {
				return nil, NonterminalWriter{testlib.FailWriter{}}, func() {}
			},
			wantErr: "nope",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			r, w, deffn := tc.rw()
			defer deffn()
			tc.inspect.Writer = w
			if err := InspectSignature(WithInspect(ctx0, tc.inspect), &epb.VMLaunchEndorsement{
				Signature: []byte{5, 1, 4},
			}); !match.Error(err, tc.wantErr) {
				t.Fatalf("InspectSignature() = %v errored unexpectedly. Want %q", err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("io.ReadAll(r) = %v errored unexpectedly", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("InspectSignature({..%v}, _) wrote %v, want %v", tc.inspect, got, tc.want)
			}
		})
	}
}

func TestInspectMask(t *testing.T) {
	ctx0 := context.Background()
	tcs := []struct {
		name        string
		ctx         context.Context
		endorsement *epb.VMLaunchEndorsement
		mask        *fmpb.FieldMask
		want        string
		wantErr     string
	}{
		{
			name: "happy path",
			ctx:  WithInspect(ctx0, &Inspect{Form: BytesRaw, Writer: NonterminalWriter{bytes.NewBufferString("")}}),
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: testlib.GoldenT(t, testGolden()),
			},
			mask: &fmpb.FieldMask{
				Paths: []string{"commit"},
			},
			want: "commit",
		},
		{
			name: "bad serialized",
			ctx:  WithInspect(ctx0, &Inspect{Form: BytesRaw, Writer: NonterminalWriter{bytes.NewBufferString("")}}),
			endorsement: &epb.VMLaunchEndorsement{
				SerializedUefiGolden: []byte("bad serialized"),
			},
			mask:    &fmpb.FieldMask{},
			wantErr: "failed to unmarshal VMGoldenMeasurement",
		},
		{
			name:    "bad ctx",
			ctx:     ctx0,
			wantErr: ErrNoInspect.Error(),
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if err := InspectMask(tc.ctx, tc.endorsement, tc.mask); !match.Error(err, tc.wantErr) {
				t.Fatalf("InspectMask({..%v}, %v, %v) = %v errored unexpectedly. Want %q", tc.ctx,
					tc.endorsement, tc.mask, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			i, _ := inspectFrom(tc.ctx)
			got := i.Writer.(NonterminalWriter).Writer.(*bytes.Buffer).String()
			if got != tc.want {
				t.Fatalf("InspectMask({..%v}, %v, %v) = %q, want %q", tc.ctx,
					tc.endorsement, tc.mask, got, tc.want)
			}
		})
	}
}
