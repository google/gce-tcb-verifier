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

package output

import (
	"errors"
	"golang.org/x/net/context"

	"os"
	"testing"

	"github.com/google/logger"
)

const (
	outTxt      = "this ought to write something unless discarded"
	outInfoN    = len(outTxt) + 1 // 1 for \n
	outDebugN   = len(debugPrefix) + len(outTxt) + 1
	outWarningN = len(warningPrefix) + len(outTxt) + 1
	outErrorN   = len(errorPrefix) + len(outTxt) + 1
)

func TestMain(m *testing.M) {
	logger.Init("log", false, false, os.Stderr)
	os.Exit(m.Run())
}

func TestContext(t *testing.T) {
	ctx0 := context.Background()
	if _, err := FromContext(ctx0); !errors.Is(err, ErrNoContext) {
		t.Errorf("FromContext(ctx0) = _, %v, want %v", err, ErrNoContext)
	}
	opts := &Options{}
	ctx := NewContext(ctx0, opts)
	if v, err := FromContext(ctx); err != nil || v != opts {
		t.Errorf("FromContext(ctx) = %v, %v, want %v", v, err, opts)
	}
}

func TestOutputs(t *testing.T) {
	tests := []struct {
		name         string
		opts         *Options
		wantInfoN    int
		wantDebugN   int
		wantWarningN int
		wantErrorN   int
		setV         int
	}{
		{
			name:         "normal",
			opts:         &Options{},
			wantInfoN:    outInfoN,
			wantDebugN:   0,
			wantWarningN: outWarningN,
			wantErrorN:   outErrorN,
		},
		{name: "quiet", opts: &Options{Quiet: true}},
		{name: "verbose",
			opts:         &Options{Verbose: true},
			wantInfoN:    outInfoN,
			wantDebugN:   outDebugN,
			wantWarningN: outWarningN,
			wantErrorN:   outErrorN,
		},
		{
			name:         "logging",
			opts:         &Options{UseLogs: true},
			wantInfoN:    1,
			wantDebugN:   0,
			wantWarningN: 1,
			wantErrorN:   1,
		},
		{
			name:         "verbose logging",
			opts:         &Options{UseLogs: true},
			setV:         1,
			wantInfoN:    1,
			wantDebugN:   1,
			wantWarningN: 1,
			wantErrorN:   1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger.SetLevel(logger.Level(tc.setV))
			ctx := NewContext(context.Background(), tc.opts)
			if n, err := Infof(ctx, outTxt); err != nil || n != tc.wantInfoN {
				t.Errorf("Infof(ctx, outTxt) = %v, %v, want %d", n, err, tc.wantInfoN)
			}
			if n, err := Debugf(ctx, outTxt); err != nil || n != tc.wantDebugN {
				t.Errorf("Debugf(ctx, outTxt) = %v, %v, want %d", n, err, tc.wantDebugN)
			}
			if n, err := Warningf(ctx, outTxt); err != nil || n != tc.wantWarningN {
				t.Errorf("Warningf(ctx, outTxt) = %v, %v, want %d", n, err, tc.wantWarningN)
			}
			if n, err := Errorf(ctx, outTxt); err != nil || n != tc.wantErrorN {
				t.Errorf("Errorf(ctx, outTxt) = %v, %v, want %d", n, err, tc.wantErrorN)
			}
			logger.SetLevel(logger.Level(0))
		})
	}
}
