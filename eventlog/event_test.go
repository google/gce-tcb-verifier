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
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/go-cmp/cmp"
)

var (
	foosha1       = [...]byte{0xf1, 0xd2, 0xd2, 0xf9, 0x24, 0xe9, 0x86, 0xac, 0x86, 0xfd, 0xf7, 0xb3, 0x6c, 0x94, 0xbc, 0xdf, 0x32, 0xbe, 0xec, 0x15}
	foosha256     = [...]byte{0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96, 0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c}
	fakeSignature = [...]byte{'f', 'a', 'k', 'e', ' ', 's', 'i', 'g', 'n', 't', 'u', 'r', 'e', 0, 0, 0}
)

func init() {
	eventFactories[hex.EncodeToString(fakeSignature[:])] = func() UnmarshallableFromBytes {
		return &UnknownEvent{}
	}
}

func TestReadTCGPCClientPCREvent(t *testing.T) {
	yukuefumei := [16]byte{'y', 'u', 'k', 'u', 'e', ' ', 'f', 'u', 'm', 'e', 'i', 0, 0, 0, 0, 0}
	tcs := []struct {
		name    string
		data    []byte
		want    *TCGPCClientPCREvent
		wantErr string
	}{
		{
			name: "happy path",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0}, foosha1[:],
				[]byte{19, 0, 0, 0}, fakeSignature[:], []byte{'f', 'o', 'o'}),
			want: &TCGPCClientPCREvent{
				PCRIndex:   uint32(2),
				EventType:  uint32(5),
				SHA1Digest: foosha1,
				EventData: TCGEventData{
					Event: &UnknownEvent{Data: []byte{'f', 'o', 'o'}},
				},
			},
		},
		{
			name: "no signature",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0}, foosha1[:],
				[]byte{3, 0, 0, 0}, []byte{'f', 'o', 'o'}),
			want: &TCGPCClientPCREvent{
				PCRIndex:   uint32(2),
				EventType:  uint32(5),
				SHA1Digest: foosha1,
				EventData: TCGEventData{
					Event: &UnknownEvent{Data: []byte{'f', 'o', 'o'}},
				},
			},
		},
		{
			name: "bad event data size",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0}, foosha1[:],
				[]byte{17, 0, 0, 0}, []byte{'f', 'o', 'o'}),
			wantErr: "failed to read TCGEventData sized 17 (read 3 bytes)",
		},
		{
			name: "unknown signature",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0}, foosha1[:],
				[]byte{17, 0, 0, 0}, yukuefumei[:], []byte{44}),
			want: &TCGPCClientPCREvent{
				PCRIndex:   uint32(2),
				EventType:  uint32(5),
				SHA1Digest: foosha1,
				EventData: TCGEventData{
					Event: &UnknownEvent{Data: combine(yukuefumei[:], []byte{44})},
				},
			},
		},
		{
			name:    "bad pcr index",
			data:    []byte{2, 0},
			wantErr: "unexpected EOF",
		},
		{
			name: "bad event type",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0},
			),
			wantErr: "unexpected EOF",
		},
		{
			name: "bad sha1",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0}, foosha1[:10],
			),
			wantErr: "failed to read SHA1Digest",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			r := bytes.NewBuffer(tc.data)
			got := &TCGPCClientPCREvent{}
			if err := got.Unmarshal(r); !match.Error(err, tc.wantErr) {
				t.Fatalf("ReadTCGPCClientPCREvent(%v) = %v errored unexpectedly. Want %q", tc.data, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ReadTCGPCClientPCREvent(%v) returned diff (-want +got):\n%s", tc.data, diff)
			}
		})
	}
}

func TestReadTCGPCREvent2(t *testing.T) {
	tcs := []struct {
		name    string
		data    []byte
		want    *TCGPCREvent2
		wantErr string
	}{
		{
			name: "happy path",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0},
				[]byte{2, 0, 0, 0},    // number of digests
				[]byte{tpmAlgSHA1, 0}, // algID uint16
				foosha1[:],
				[]byte{tpmAlgSHA256, 0}, // algID uint16
				foosha256[:],
				[]byte{19, 0, 0, 0}, fakeSignature[:], []byte{'f', 'o', 'o'}),
			want: &TCGPCREvent2{
				PCRIndex:  2,
				EventType: 5,
				Digests: Uint32SizedArrayT[*TaggedDigest]{Array: []*TaggedDigest{
					{AlgID: tpmAlgSHA1, Digest: foosha1[:]},
					{AlgID: tpmAlgSHA256, Digest: foosha256[:]},
				}},
				EventData: TCGEventData{
					Event: &UnknownEvent{Data: []byte{'f', 'o', 'o'}},
				},
			},
		},
		{
			name: "unsupported digest algorithm",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0},
				[]byte{1, 0, 0, 0}, // number of digests
				[]byte{0xc0, 0xde}, // algID uint16
				foosha1[:],
				[]byte{19, 0, 0, 0}, fakeSignature[:], []byte{'f', 'o', 'o'}),
			wantErr: "unsupported digest algorithm 57024",
		},
		{
			name: "digest read failure",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0},
				[]byte{1, 0, 0, 0},    // number of digests
				[]byte{tpmAlgSHA1, 0}, // algID uint16
				[]byte(`not enough`)),
			wantErr: "failed to read digest",
		},
		{
			name:    "bad pcr index",
			data:    []byte{2, 0},
			wantErr: "unexpected EOF",
		},
		{
			name:    "bad event type",
			data:    []byte{2, 0, 0, 0, 5, 0},
			wantErr: "unexpected EOF",
		},
		{
			name: "unsupported signature",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0},
				[]byte{2, 0, 0, 0},    // number of digests
				[]byte{tpmAlgSHA1, 0}, // algID uint16
				foosha1[:],
				[]byte{tpmAlgSHA256, 0}, // algID uint16
				foosha256[:],
				[]byte{16, 0, 0, 0},
				[]byte(`no entry forthis`)),
			want: &TCGPCREvent2{
				PCRIndex:  2,
				EventType: 5,
				Digests: Uint32SizedArrayT[*TaggedDigest]{Array: []*TaggedDigest{
					{AlgID: tpmAlgSHA1, Digest: foosha1[:]},
					{AlgID: tpmAlgSHA256, Digest: foosha256[:]},
				}},
				EventData: TCGEventData{
					Event: &UnknownEvent{Data: []byte(`no entry forthis`)},
				},
			},
		},
		{
			name: "bad eventdata size",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0},
				[]byte{2, 0, 0, 0}, // number of digests
				[]byte{tpmAlgSHA1, 0},
				foosha1[:],
				[]byte{tpmAlgSHA256, 0},
				foosha256[:],
				[]byte{16, 0}),
			wantErr: "unexpected EOF",
		},
		{
			name: "bad algid",
			data: combine([]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0},
				[]byte{1, 0, 0, 0},
				[]byte{tpmAlgSHA1}),
			wantErr: "unexpected EOF",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			r := bytes.NewBuffer(tc.data)
			got := &TCGPCREvent2{}
			if err := got.Unmarshal(r); !match.Error(err, tc.wantErr) {
				t.Fatalf("ReadTCGPCREvent2(%v) = %v errored unexpectedly. Want %q", tc.data, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ReadTCGPCREvent2(%v) returned diff (-want +got):\n%s", tc.data, diff)
			}
		})
	}
}

func TestReadCryptoAgileLog(t *testing.T) {
	tcs := []struct {
		name    string
		data    []byte
		want    *CryptoAgileLog
		wantErr string
	}{
		{
			name: "happy path",
			data: combine(
				// TCGPCClientPCREvent
				[]byte{2, 0, 0, 0},
				[]byte{5, 0, 0, 0}, foosha1[:],
				[]byte{19, 0, 0, 0}, fakeSignature[:], []byte{'f', 'o', 'o'},
				// TCG2PCREvent
				[]byte{3, 0, 0, 0},
				[]byte{7, 0, 0, 0},
				[]byte{2, 0, 0, 0},    // number of digests
				[]byte{tpmAlgSHA1, 0}, // algID uint16
				foosha1[:],
				[]byte{tpmAlgSHA256, 0}, // algID uint16
				foosha256[:],
				[]byte{19, 0, 0, 0}, fakeSignature[:], []byte{'f', 'o', 'o'}),
			want: &CryptoAgileLog{
				Header: TCGPCClientPCREvent{
					PCRIndex:   2,
					EventType:  5,
					SHA1Digest: foosha1,
					EventData: TCGEventData{
						Event: &UnknownEvent{Data: []byte{'f', 'o', 'o'}},
					},
				},
				Events: []*TCGPCREvent2{
					{
						PCRIndex:  3,
						EventType: 7,
						Digests: Uint32SizedArrayT[*TaggedDigest]{Array: []*TaggedDigest{
							{AlgID: tpmAlgSHA1, Digest: foosha1[:]},
							{AlgID: tpmAlgSHA256, Digest: foosha256[:]},
						}},
						EventData: TCGEventData{
							Event: &UnknownEvent{Data: []byte{'f', 'o', 'o'}},
						},
					},
				},
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			r := bytes.NewBuffer(tc.data)
			got := &CryptoAgileLog{}
			if err := got.Unmarshal(r); !match.Error(err, tc.wantErr) {
				t.Fatalf("ReadCryptoAgileLog(%v) = %v errored unexpectedly. Want %q", tc.data, err, tc.wantErr)
			}
			if tc.wantErr != "" {
				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ReadCryptoAgileLog(%v) returned diff (-want +got):\n%s", tc.data, diff)
			}
		})
	}
}
