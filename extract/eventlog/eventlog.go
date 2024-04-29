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

// Package eventlog provides utilities for interpreting Canonical Event Log events.
package eventlog

import (
	"errors"
	"fmt"

	"github.com/google/gce-tcb-verifier/eventlog"
	oabi "github.com/google/gce-tcb-verifier/ovmf/abi"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/google/uuid"
)

// ErrLocateGetterNil is returned when a LocateOptions.Getter is nil.
var ErrLocateGetterNil = errors.New("locate getter is nil")

// LocateOptions contains options for locating data that can be local or remote.
type LocateOptions struct {
	Getter             trust.HTTPSGetter
	UEFIVariableReader VariableReader
}

// DefaultLocateOptions returns a default LocateOptions.
func DefaultLocateOptions() *LocateOptions {
	return &LocateOptions{
		Getter:             trust.DefaultHTTPSGetter(),
		UEFIVariableReader: MakeEfiVarFSReader("/sys/firmware/efi/efivars"),
	}
}

func variableLocatorDecode(loc []byte) (uuid.UUID, []uint8, error) {
	// 16 for guid, 2 for 00-terminator.
	if len(loc) <= 18 {
		return uuid.UUID{}, nil, fmt.Errorf("variable name is too short: %d bytes", len(loc))
	}
	guid, _ := oabi.FromEFIGUID(loc[:16])
	name := loc[16:] // at least size 1
	if len(name)%2 != 0 {
		return uuid.UUID{}, nil, fmt.Errorf("couldn't read variable name as UCS-2 string: %v", name)
	}
	if !(name[len(name)-1] == 0 && name[len(name)-2] == 0) {
		return uuid.UUID{}, nil, fmt.Errorf("couldn't read variable name as 00-terminated UCS-2 string")
	}
	return guid, name, nil
}

// Locate returns the value of a RIM locator.
func Locate(locType uint32, loc []byte, opts *LocateOptions) ([]byte, error) {
	switch locType {
	case eventlog.RIMLocationRaw:
		return loc, nil
	case eventlog.RIMLocationURI:
		if opts.Getter == nil {
			return nil, ErrLocateGetterNil
		}
		return opts.Getter.Get(string(loc))
	case eventlog.RIMLocationVariable:
		guid, name, err := variableLocatorDecode(loc)
		if err != nil {
			return nil, err
		}
		return opts.UEFIVariableReader.ReadVariable(guid, name)
	default:
		return nil, fmt.Errorf("unsupported locator type: %v", locType)
	}
}

// RIMEventsFromEventLog returns a map of RIM locator type to a slice of SP800-155 Event3 events
// that match the RIM locator type.
func RIMEventsFromEventLog(el *eventlog.CryptoAgileLog) map[uint32][]*eventlog.SP800155Event3 {
	result := make(map[uint32][]*eventlog.SP800155Event3)
	for _, evt := range el.Events {
		if evt.EventType != eventlog.EvNoAction || evt.EventData.Event == nil {
			continue
		}
		sp800155, ok := evt.EventData.Event.(*eventlog.SP800155Event3)
		if !ok {
			continue
		}
		result[sp800155.RIMLocatorType] = append(result[sp800155.RIMLocatorType], sp800155)
	}
	return result
}
