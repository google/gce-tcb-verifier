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

package extract

import (
	"fmt"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
)

// ConfigfsTsmQuoteProvider provides quotes through the Linux configfs-tsm report interface.
type ConfigfsTsmQuoteProvider struct {
	Client configfsi.Client
}

// IsSupported returns true if the quote provider supports configfs-tsm reports.
func (qp *ConfigfsTsmQuoteProvider) IsSupported() bool {
	if qp.Client != nil {
		return true
	}
	cl, err := linuxtsm.MakeClient()
	qp.Client = cl
	return err == nil
}

// GetRawQuote returns the raw quote from the configfs-tsm report.
func (qp *ConfigfsTsmQuoteProvider) GetRawQuote(reportData [64]byte) ([]uint8, error) {
	if qp.Client == nil {
		cl, err := linuxtsm.MakeClient()
		if err != nil {
			return nil, fmt.Errorf("quote provider used outside IsSupported guard: %v", err)
		}
		qp.Client = cl
	}

	resp, err := report.Get(qp.Client, &report.Request{InBlob: reportData[:]})
	if err != nil {
		return nil, err
	}
	return resp.OutBlob, nil
}
