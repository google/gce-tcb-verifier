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

// Package storage provides a mock rotate.StorageClient implementation
package storage

import (
	"bytes"
	"golang.org/x/net/context"
	"io"
	"os"
)

// ReaderResponse is the reader or error that Reader returns for a specific object.
type ReaderResponse struct {
	ReaderMaker func() io.ReadCloser
	Err         error
}

// WriterResponse is the writer or error that Writer returns for a specific object.
type WriterResponse struct {
	Writer io.WriteCloser
	Err    error
}

// EnsureBucketExistsResponse is the result of EnsureBucketExists for a given bucket.
type EnsureBucketExistsResponse struct {
	Err error
}

// Responses is a representation of the Reader and Writer responses at an object granularity.
type Responses struct {
	// If there is content, then it's stored here in Cell.
	Cell      *FakeObject
	ReadResp  *ReaderResponse
	WriteResp *WriterResponse
}

// Mock implements the rotate.StorageClient interface to mock object contents.
type Mock struct {
	BucketObjects   map[string]map[string]*Responses
	EnsureResponses map[string]*EnsureBucketExistsResponse
	// Return this error from all operations for simple error specification.
	err error
}

type nopCloser struct {
	io.Reader
}

func (n *nopCloser) Close() error { return nil }

// FakeObject is a cell that can be used by readers and writers alike to manipulate an object's
// contents.
type FakeObject struct {
	Data []byte
}

// ObjectWriter is an io.Writer that overwrites/creates a FakeObject with Content, or returns an
// error on Close().
type ObjectWriter struct {
	M *Mock

	Bucket   string
	Object   string
	Content  []byte
	WriteErr error
	CloseErr error
}

// ObjectReader is an io.Reader that reads a FakeObject or errors, and returns an error on Close().
type ObjectReader struct {
	ReadErr  error
	CloseErr error
}

func (r *ObjectReader) Read(b []byte) (int, error) {
	return 0, r.ReadErr
}

// Close returns the canned CloseErr.
func (r *ObjectReader) Close() error { return r.CloseErr }

// Write updates the Writer with b as additional content to be appended, or returns a canned error.
func (w *ObjectWriter) Write(b []byte) (int, error) {
	if w.WriteErr != nil {
		return 0, w.WriteErr
	}
	w.Content = append(w.Content, b...)
	return len(b), nil
}

// Close commits Writer changes back to the Storage representation, or returns a canned error.
func (w *ObjectWriter) Close() error {
	if w.CloseErr != nil {
		return w.CloseErr
	}

	writer := *w
	writer.Content = nil
	result := &Responses{
		// This may be overwritten if the object already exists
		Cell:      &FakeObject{Data: w.Content},
		WriteResp: &WriterResponse{Writer: &writer},
	}

	if w.M.BucketObjects == nil {
		w.M.BucketObjects = make(map[string]map[string]*Responses)
	}
	bucket, ok := w.M.BucketObjects[w.Bucket]
	if !ok {
		// There is no bucket for w.Bucket, so the whole bucket must be populated by a single object.
		w.M.BucketObjects[w.Bucket] = map[string]*Responses{w.Object: result}
	} else {
		if resp, ok := bucket[w.Object]; ok {
			result.Cell = resp.Cell
			result.Cell.Data = w.Content
		}
		bucket[w.Object] = result
	}
	result.ReadResp = &ReaderResponse{ReaderMaker: mkReaderMaker(result.Cell)}
	return nil
}

func (s *Mock) Reader(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
	if s.err != nil {
		return nil, s.err
	}
	if objs, ok := s.BucketObjects[bucket]; ok {
		if resps, ok := objs[object]; ok {
			if resps.ReadResp.Err != nil {
				return nil, resps.ReadResp.Err
			}
			return resps.ReadResp.ReaderMaker(), nil
		}
	}
	return nil, os.ErrNotExist
}

func (s *Mock) Exists(ctx context.Context, bucket, object string) (bool, error) {
	if _, err := s.Reader(ctx, bucket, object); err != nil {
		if s.IsNotExists(err) {
			err = nil
		}
		return false, err
	}
	return true, s.err
}

func (s *Mock) Writer(ctx context.Context, bucket, object string) (io.WriteCloser, error) {
	if s.err != nil {
		return nil, s.err
	}
	if objs, ok := s.BucketObjects[bucket]; ok {
		if resps, ok := objs[object]; ok {
			if resps.WriteResp.Err != nil {
				return nil, resps.WriteResp.Err
			}
			return resps.WriteResp.Writer, nil
		}
	}
	return &ObjectWriter{M: s, Bucket: bucket, Object: object}, nil
}

// IsNotExists returns whether an error returned from Mock represents the NotExists error.
func (s *Mock) IsNotExists(err error) bool {
	return os.IsNotExist(err)
}

// EnsureBucketExists does nothing.
func (s *Mock) EnsureBucketExists(ctx context.Context, bucket string) error {
	if s.err != nil {
		return s.err
	}
	result, ok := s.EnsureResponses[bucket]
	if !ok {
		return nil // Treat a lack of a result as no error
	}
	return result.Err
}

func mkReaderMaker(cell *FakeObject) func() io.ReadCloser {
	return func() io.ReadCloser { return &nopCloser{bytes.NewReader(cell.Data)} }
}

// WithInitialContents returns an initial Mock implementation with objects with the given contents
// all in the same bucket.
func WithInitialContents(initialContents map[string][]byte, bucket string) *Mock {
	m := &Mock{}
	contentsCopy := make(map[string]*Responses)
	for k, v := range initialContents {
		result := &Responses{Cell: &FakeObject{Data: v}}
		result.ReadResp = &ReaderResponse{ReaderMaker: mkReaderMaker(result.Cell)}
		result.WriteResp = &WriterResponse{Writer: &ObjectWriter{M: m, Bucket: bucket, Object: k}}
		contentsCopy[k] = result
	}

	m.BucketObjects = map[string]map[string]*Responses{bucket: contentsCopy}
	return m
}

// Clone returns a new Mock with all objects containing the same contents in new cells.
func (s *Mock) Clone() *Mock {
	result := &Mock{
		BucketObjects:   make(map[string]map[string]*Responses),
		EnsureResponses: make(map[string]*EnsureBucketExistsResponse),
		err:             s.err,
	}
	cloneResponse := func(bucket, objName string, resp *Responses) *Responses {
		cell := &FakeObject{Data: bytes.Clone(resp.Cell.Data)}
		return &Responses{
			Cell:     cell,
			ReadResp: &ReaderResponse{ReaderMaker: mkReaderMaker(cell), Err: resp.ReadResp.Err},
			WriteResp: &WriterResponse{Writer: &ObjectWriter{
				M:        result,
				Bucket:   bucket,
				Object:   objName,
				WriteErr: resp.WriteResp.Err,
			}},
		}
	}
	cloneObjs := func(bucket string, objs map[string]*Responses) map[string]*Responses {
		robjs := make(map[string]*Responses)
		for objName, resp := range objs {
			robjs[objName] = cloneResponse(bucket, objName, resp)
		}
		return robjs
	}
	for b, objs := range s.BucketObjects {
		result.BucketObjects[b] = cloneObjs(b, objs)
	}
	for b, resp := range s.EnsureResponses {
		ensureCopy := *resp
		result.EnsureResponses[b] = &ensureCopy
	}
	return result
}

// Wipeout deletes all objects under the given bucket.
func (s *Mock) Wipeout(ctx context.Context, bucket string) error {
	if _, ok := s.BucketObjects[bucket]; !ok {
		return os.ErrNotExist
	}
	s.BucketObjects[bucket] = nil
	return nil
}

// WithError returns an initial Mock implementation that always returns the given error.
func WithError(err error) *Mock {
	return &Mock{err: err}
}
