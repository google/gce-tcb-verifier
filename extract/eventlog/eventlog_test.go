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

package eventlog

import (
	"os"
	"path"
	"testing"

	"github.com/google/gce-tcb-verifier/eventlog"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/go-cmp/cmp"
	test "github.com/google/go-sev-guest/testing"
)

const (
	myGUID  = "6a7b6885-92bc-40cd-9fb5-300f9d1eb0ed"
	rimGUID = "c51b6d7f-9c2a-42d6-be47-ca1368bdc333"
)

var myEfiGUID = []byte{0x85, 0x68, 0x7b, 0x6a, 0xbc, 0x92, 0xcd, 0x40, 0x9f, 0xb5, 0x30, 0x0f, 0x9d, 0x1e, 0xb0, 0xed}

func TestUEFIVariable(t *testing.T) {
	tcs := []struct {
		name    string
		data    []byte
		want    string
		wantErr string
	}{
		{
			name: "happy path",
			data: append(myEfiGUID, 'V', 0, 'a', 0, 'r', 0, 0, 0),
			want: "/Var-" + myGUID,
		},
		{
			name:    "happy utf-16, unhappy UCS-2",
			data:    append(myEfiGUID, 0x3c, 0xd8, 0x89, 0xdf, 0, 0),
			wantErr: "codepoint 0x1f389 is unrepresentable in UCS-2",
		},
		{
			name: "happy UCS-2",
			data: append(myEfiGUID, 0x22, 0x6f, 0x57, 0x5b, 0x27, 0x59, 0x7d, 0x59, 0x4d, 0x30, 0, 0),
			want: "/漢字大好き-" + myGUID,
		},
		{
			name:    "odd length",
			data:    append(myEfiGUID, 'V', 0, 'a', 0, 'r', 0, 0),
			wantErr: "couldn't read variable name as UCS-2 string",
		},
		{
			name:    "bad terminator no zeros",
			data:    append(myEfiGUID, 'V', 0, 'a', 0, 'r', 0),
			wantErr: "00-terminated UCS-2 string",
		},
		{
			name:    "too short",
			data:    []byte{0, 1},
			wantErr: "too short: 2 bytes",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var out string
			guid, name, err := variableLocatorDecode(tc.data)
			if err == nil {
				out, err = MakeEfiVarFSReader("").varBasename(guid, name)
			}
			if !match.Error(err, tc.wantErr) {
				t.Fatalf("variableLocatorDecode(_, %v) = %v errored unexpectedly. Want %q", tc.data, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if out != tc.want {
				t.Errorf("variableLocatorDecode(_, %v) wrote %q, want %q", tc.data, out, tc.want)
			}
		})
	}
}

func TestLocate(t *testing.T) {
	dir := t.TempDir()
	dir2 := t.TempDir()
	varloc := path.Join(dir, "Var-"+myGUID)
	varloc2 := path.Join(dir2, "Var-"+myGUID)
	err := os.WriteFile(varloc, []byte{7, 0, 0, 0, 0xc0, 0xde}, 0644)
	if err != nil {
		t.Fatalf("os.WriteFile(%q) = %v, want nil", varloc, err)
	}
	// no 4-byte attribute header.
	err = os.WriteFile(varloc2, []byte{0xc0, 0xde}, 0644)
	if err != nil {
		t.Fatalf("os.WriteFile(%q) = %v, want nil", varloc, err)
	}
	tcs := []struct {
		name    string
		loctype uint32
		loc     []byte
		opts    *LocateOptions
		want    []byte
		wantErr string
	}{
		{
			name:    "happy raw",
			loctype: eventlog.RIMLocationRaw,
			loc:     []byte{0xc0, 0xde},
			opts:    &LocateOptions{},
			want:    []byte{0xc0, 0xde},
		},
		{
			name:    "happy uri",
			loctype: eventlog.RIMLocationURI,
			loc:     []byte("uri"),
			opts: &LocateOptions{
				Getter: test.SimpleGetter(map[string][]byte{
					"uri": {0xc0, 0xde},
				}),
			},
			want: []byte{0xc0, 0xde},
		},
		{
			name:    "uri 404",
			loctype: eventlog.RIMLocationURI,
			loc:     []byte("uri"),
			opts: &LocateOptions{
				Getter: test.SimpleGetter(map[string][]byte{}),
			},
			wantErr: "404", // SimpleGetter behavior for unmapped URI.
		},
		{
			name:    "uri no getter",
			loctype: eventlog.RIMLocationURI,
			loc:     []byte("uri"),
			opts:    &LocateOptions{},
			wantErr: ErrLocateGetterNil.Error(),
		},
		{
			name:    "happy variable",
			loc:     append(myEfiGUID, 'V', 0, 'a', 0, 'r', 0, 0, 0),
			loctype: eventlog.RIMLocationVariable,
			opts: &LocateOptions{
				UEFIVariableReader: MakeEfiVarFSReader(dir),
			},
			want: []byte{0xc0, 0xde},
		},
		{
			name:    "no efivarfs attributes",
			loc:     append(myEfiGUID, 'V', 0, 'a', 0, 'r', 0, 0, 0),
			loctype: eventlog.RIMLocationVariable,
			opts: &LocateOptions{
				UEFIVariableReader: MakeEfiVarFSReader(dir2),
			},
			wantErr: "variable contents ill-formed. [192 222] does not start with 4-byte attribute header",
		},
		{
			name:    "unhappy variable",
			loc:     []byte{0xc0, 0xde},
			loctype: eventlog.RIMLocationVariable,
			wantErr: "variable name is too short: 2 bytes",
		},
		{
			name:    "unsupported locator",
			loctype: 999,
			wantErr: "unsupported locator type: 999",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Locate(tc.loctype, tc.loc, tc.opts)
			if !match.Error(err, tc.wantErr) {
				t.Fatalf("Locate(%v, %v, %v) errored unexpectedly. Got %v, want %q", tc.loctype,
					tc.loc, tc.opts, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("Locate(%v, %v, %v) returned diff (-got +want):\n%s", tc.loctype,
					tc.loc, tc.opts, diff)
			}
		})
	}
}

func TestRimEventsFromEventLog(t *testing.T) {
	tests := []struct {
		name string
		el   *eventlog.CryptoAgileLog
		want map[uint32][]*eventlog.SP800155Event3
	}{
		{
			name: "happy path",
			el: &eventlog.CryptoAgileLog{
				Header: eventlog.TCGPCClientPCREvent{
					PCRIndex:  1,
					EventType: 10,
					EventData: eventlog.TCGEventData{Event: &eventlog.UnknownEvent{}},
				},
				Events: []*eventlog.TCGPCREvent2{
					{EventType: 99},
					{
						EventType: eventlog.EvNoAction,
						EventData: eventlog.TCGEventData{Event: &eventlog.UnknownEvent{}},
					},
					{
						EventType: eventlog.EvNoAction,
						EventData: eventlog.TCGEventData{
							Event: &eventlog.SP800155Event3{
								RIMLocatorType: eventlog.RIMLocationVariable,
								RIMLocator:     eventlog.Uint32SizedArray{Data: append(myEfiGUID, 'V', 0, 'a', 0, 'r', 0, 0, 0)},
							}},
					},
					{
						EventType: eventlog.EvNoAction,
						EventData: eventlog.TCGEventData{
							Event: &eventlog.SP800155Event3{
								RIMLocatorType: eventlog.RIMLocationVariable,
								RIMLocator:     eventlog.Uint32SizedArray{Data: append(myEfiGUID, 'V', 0, 'a', 0, 'r', 0, '2', 0, 0, 0)},
							}},
					},
					{
						EventType: eventlog.EvNoAction,
						EventData: eventlog.TCGEventData{
							Event: &eventlog.SP800155Event3{
								RIMLocatorType: eventlog.RIMLocationURI,
								RIMLocator:     eventlog.Uint32SizedArray{Data: []byte("https://example.com")},
							}},
					},
				},
			},
			want: map[uint32][]*eventlog.SP800155Event3{
				eventlog.RIMLocationVariable: {
					{
						RIMLocatorType: eventlog.RIMLocationVariable,
						RIMLocator:     eventlog.Uint32SizedArray{Data: append(myEfiGUID, 'V', 0, 'a', 0, 'r', 0, 0, 0)},
					},
					{
						RIMLocatorType: eventlog.RIMLocationVariable,
						RIMLocator:     eventlog.Uint32SizedArray{Data: append(myEfiGUID, 'V', 0, 'a', 0, 'r', 0, '2', 0, 0, 0)},
					},
				},
				eventlog.RIMLocationURI: {
					{
						RIMLocatorType: eventlog.RIMLocationURI,
						RIMLocator:     eventlog.Uint32SizedArray{Data: []byte("https://example.com")},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := RIMEventsFromEventLog(tc.el)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("RIMEventsFromEventLog(%v) returned an unexpected diff (-want +got): %v", tc.el, diff)
			}
		})
	}
}
