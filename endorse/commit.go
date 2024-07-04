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

package endorse

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"

	"github.com/google/gce-tcb-verifier/cmd/output"
	"github.com/google/gce-tcb-verifier/keys"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	rpb "github.com/google/gce-tcb-verifier/proto/releases"
	"github.com/google/gce-tcb-verifier/timeproto"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

var (
	endorsementFileExt = "binarypb"
	// ErrNoRetries is returned when submit fails too many times to continue attempting submission.
	// The retry amount is settable through Options.
	ErrNoRetries = errors.New("ran out of submit retries")
	// ErrNoEndorseContext is returned when the context.Context object does not contain the
	// EndorseContext.
	ErrNoEndorseContext = errors.New("no EndorseContext found")
	// ManifestFile is the basename of the VMEndorsementMap signature manifest.
	ManifestFile = "manifest.textproto"
	// DefaultEndorsementBasename is used for the file basename (minus file extension) of the signed
	// UEFI golden measurement, AKA the UEFI endorsement.
	DefaultEndorsementBasename = "endorsement"
	manifestTextProtoPreamble  = `
# proto-file: github.com/google/gce-tcb-verifier/proto/releases.proto
# proto-message: VMEndorsementMap
# !!! THIS FILE WAS AUTOMATICALLY GENERATED !!!
# !!! DO NOT MODIFY BY HAND !!!

`
)

// VersionControl abstracts the necessary operations for transacting signature files into a version
// control system.
type VersionControl interface {
	// GetChangeOps returns a filesystem abstraction within the context of a commit attempt.
	GetChangeOps(ctx context.Context) (ChangeOps, error)
	// RetriableError returns true if TryCommit's provided error is retriable.
	RetriableError(err error) bool
	// Result returns a successful commit's representation given a successful TryCommit's result and
	// the path to the created endorsement.
	Result(commit any, endorsementPath string) any
	// ReleasePath translates a path to its expected full path for WriteOrCreateFiles/ReadFile.
	ReleasePath(ctx context.Context, certPath string) string
}

// CommitFinalizer performs any final actions with the commit result of the endorsement
// signatures.
type CommitFinalizer interface {
	// Finalize performs any final actions with the VersionControl Result value.
	Finalize(ctx context.Context, result any) error
}

// File represents a file's path and contents.
type File struct {
	Path     string
	Contents []byte
}

// ChangeOps abstracts file IO for reading, writing, querying files, and committing to the
// EndorseInterface.
type ChangeOps interface {
	// WriteOrCreateFiles creates or overwrites all given files with their paired contents, or returns
	// an error.
	WriteOrCreateFiles(ctx context.Context, files ...*File) error
	// ReadFile returns the content of the given file, or an error.
	ReadFile(ctx context.Context, path string) ([]byte, error)
	// SetBinaryWritable sets the metadata of the given file to denote it as binary and writable, and
	// returns nil on success.
	SetBinaryWritable(ctx context.Context, path string) error
	// IsNotFound returns if any errors returned by the implementation should be interpreted as file
	// not found.
	IsNotFound(err error) bool
	// Destroy reclaims any resources this object is using.
	Destroy()
	// TryCommit returns a representation of the successful commit or an error.
	TryCommit(ctx context.Context) (any, error)
}

// Returns an error if entries has multiple references to the same file, otherwise returns a map of
// file path to entry as well as digest hexstring to entry.
func entryMaps(entries []*rpb.VMEndorsementMap_Entry) (files, digests map[string]*rpb.VMEndorsementMap_Entry, err error) {
	files = make(map[string]*rpb.VMEndorsementMap_Entry)
	digests = make(map[string]*rpb.VMEndorsementMap_Entry)
	for _, entry := range entries {
		existing, ok := files[entry.Path]
		if ok {
			return nil, nil, fmt.Errorf("endorsement map has duplicate references to file %q from %v and %v",
				entry.Path, existing, entry)
		}
		digest := hex.EncodeToString(entry.Digest)
		existing, ok = digests[digest]
		if ok {
			return nil, nil, fmt.Errorf("endorsement map has duplicate references to digest %q from %v and %v",
				entry.Digest, existing, entry)
		}
		files[entry.Path] = entry
		digests[digest] = entry
	}
	return files, digests, nil
}

func releasePath(ctx context.Context, basename string) string {
	ec, _ := FromContext(ctx)
	return ec.VCS.ReleasePath(ctx, path.Join(ec.OutDir, basename))
}

func fileExists(ctx context.Context, cops ChangeOps, fullpath string) (bool, error) {
	_, err := cops.ReadFile(ctx, fullpath)
	if cops.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// defaultGenerateBasename returns a certificate file name to use for the endorsement request. If the
// CandidateName field is present in the request, then the name is customizable. Defaults to
// 'endorsement.binarypb'.
func defaultGenerateBasename(ctx context.Context, cops ChangeOps) (string, error) {
	ec, err := FromContext(ctx)
	if err != nil {
		return "", err
	}
	release := ec.CandidateName
	if release == "" {
		release = DefaultEndorsementBasename
	}
	basename := fmt.Sprintf("%s.%s", release, endorsementFileExt)
	path := releasePath(ctx, basename)
	exists, err := fileExists(ctx, cops, path)
	if err != nil {
		return "", err
	}
	if !exists || output.AllowOverwrite(ctx) {
		return basename, nil
	}
	// A counter-based name is out of reach. Use a default name.
	return "", fmt.Errorf("cannot overwrite existing file without --overwrite %s", path)
}

func removeDigest(entries []*rpb.VMEndorsementMap_Entry, digest string) []*rpb.VMEndorsementMap_Entry {
	result := []*rpb.VMEndorsementMap_Entry{}
	for _, entry := range entries {
		if hex.EncodeToString(entry.Digest) != digest {
			result = append(result, entry)
		}
	}
	return result
}

// Whenever a create candidate workflow runs, the signer will run. This can include a forced rerun
// on the same candidate. When that happens, we only need to update the creation time of the
// existing entry.
//
// If the digest has not changed at all from a previous cut, then we update the path and the
// creation time. We don't keep the previous file since the fresh signature has more longevity.
//
// If the path for the candidate exists, then we're going to overwrite the endorsement. The digest
// for the entry should be updated too.
//
// If the path and digest both exist but are in different entries, then we remove the old digest
// entry and update the path entry since this corresponds to a refreshed candidate with a different
// digest.
func addEndorsementEntry(ctx context.Context,
	entries []*rpb.VMEndorsementMap_Entry,
	entry *rpb.VMEndorsementMap_Entry) []*rpb.VMEndorsementMap_Entry {
	files, digests, err := entryMaps(entries)
	if err != nil {
		output.Errorf(ctx, "initial manifest ill-formed: %v", err)
	}
	digest := hex.EncodeToString(entry.Digest)
	oldPath, hasPath := files[entry.Path]
	oldDigest, hasDigest := digests[digest]
	if !hasPath && !hasDigest {
		return append(entries, entry)
	}
	var modify *rpb.VMEndorsementMap_Entry
	if hasPath {
		if hasDigest && oldPath != oldDigest {
			entries = removeDigest(entries, digest)
		}
		modify = oldPath
	} else {
		modify = oldDigest
	}

	modify.Digest = entry.Digest
	modify.CreateTime = entry.GetCreateTime()
	modify.Path = entry.Path

	return entries
}

func writeEndorsement(ctx context.Context, path string, endorsement *epb.VMLaunchEndorsement, cops ChangeOps) error {
	endorsementBytes, err := proto.Marshal(endorsement)
	if err != nil {
		return fmt.Errorf("failed to marshal endorsement binary proto: %w", err)
	}
	if err := cops.WriteOrCreateFiles(ctx,
		&File{Path: path, Contents: endorsementBytes}); err != nil {
		return err
	}
	// The endorsement is a binarypb, but files are default text. We have to change it to binary.
	if err := cops.SetBinaryWritable(ctx, path); err != nil {
		return fmt.Errorf("could not set %q type to binary: %w", path, err)
	}
	return nil
}

func addEndorsement(ctx context.Context,
	cops ChangeOps,
	endorsementMap *rpb.VMEndorsementMap,
	endorsement *epb.VMLaunchEndorsement) (string, error) {
	ec, err := FromContext(ctx)
	if err != nil {
		return "", err
	}

	basename, err := defaultGenerateBasename(ctx, cops)
	if err != nil {
		return "", err
	}
	path := releasePath(ctx, basename)
	if err := writeEndorsement(ctx, path, endorsement, cops); err != nil {
		return "", err
	}
	digest := sha512.Sum384(ec.Image)
	newEntries := addEndorsementEntry(ctx, endorsementMap.Entries,
		&rpb.VMEndorsementMap_Entry{
			Digest:     digest[:],
			Path:       basename,
			CreateTime: timeproto.To(ec.Timestamp),
		})
	endorsementMap.Entries = newEntries

	return basename, nil
}

func snapshotEndorsement(ctx context.Context, cops ChangeOps, endorsement *epb.VMLaunchEndorsement) error {
	ec, err := FromContext(ctx)
	if err != nil {
		return err
	}
	fwPath := ec.VCS.ReleasePath(ctx, path.Join(ec.SnapshotDir, ec.ImageName))
	sigPath := fmt.Sprintf("%s.signed", fwPath)
	evtsPath := fmt.Sprintf("%s.evts.pb", fwPath)
	if err := writeEndorsement(ctx, sigPath, endorsement, cops); err != nil {
		return err
	}
	var random io.Reader
	k, err := keys.FromContext(ctx)
	if err != nil {
		random = rand.Reader
	} else {
		random = k.Random
	}
	events, err := makeEvents(random, endorsement)
	if err != nil {
		return err
	}
	if err := cops.WriteOrCreateFiles(ctx,
		&File{Path: fwPath, Contents: ec.Image},
		&File{Path: evtsPath, Contents: events}); err != nil {
		return err
	}
	if err := cops.SetBinaryWritable(ctx, fwPath); err != nil {
		return fmt.Errorf("could not set %q type to binary: %w", fwPath, err)
	}
	if err := cops.SetBinaryWritable(ctx, evtsPath); err != nil {
		return fmt.Errorf("could not set %q type to binary: %w", evtsPath, err)
	}
	return nil
}

// Updates the workspace's changelist to add a new entry to the manifest mapping the requested
// UEFI's checksum to the endorsement's file path, and writes the serialized endorsement to that
// path.
func changeEndorsements(ctx context.Context, cops ChangeOps, endorsement *epb.VMLaunchEndorsement) (string, error) {
	ec, err := FromContext(ctx)
	if err != nil {
		return "", err
	}

	// Snapshotting removes the need for the firmware mpm and its manifest entirely.
	if ec.SnapshotDir != "" {
		if err := snapshotEndorsement(ctx, cops, endorsement); err != nil {
			return "", err
		}
		return "", nil
	}

	var manifestTextProto []byte
	if !ec.DryRun {
		path := releasePath(ctx, ManifestFile)
		bs, err := cops.ReadFile(ctx, path)
		if !cops.IsNotFound(err) && err != nil {
			return "", fmt.Errorf("failed to read manifest textproto %q: %w", path, err)
		}
		manifestTextProto = bs
	}

	endorsementMap := &rpb.VMEndorsementMap{}
	if err := prototext.Unmarshal(manifestTextProto, endorsementMap); err != nil {
		return "", fmt.Errorf("failed to unmarshal endorsement binary proto: %w", err)
	}
	certPath, err := addEndorsement(ctx, cops, endorsementMap, endorsement)
	if err != nil {
		return "", err
	}

	// Commit the map in text for human-readable diffs.
	newTextProto, err := prototext.Marshal(endorsementMap)
	if err != nil {
		return "", fmt.Errorf("failed to marshal extended manifest textproto: %w", err)
	}
	// Avoid the "missing trailing newline" error for the textproto by adding a newline.
	contents := append(append([]byte(manifestTextProtoPreamble), newTextProto...),
		'\n')
	path := releasePath(ctx, ManifestFile)
	if !ec.DryRun {
		output.Debugf(ctx, "Writing updated manifest as %s", path)
		if err := cops.WriteOrCreateFiles(ctx,
			&File{Path: path, Contents: contents}); err != nil {
			return "", fmt.Errorf("failed to write or create manifest textproto %q: %w", path, err)
		}
	} else {
		output.Infof(ctx, "dry run: would write manifest %q", path)
	}
	return certPath, nil
}

// Creates commit for extending the endorsement manifest and writing out the serialized endorsement
// and attempts to submit. Submit may fail, thus "try".
func tryChange(ctx context.Context, change func(context.Context, ChangeOps) (string, error)) (any, error) {
	ec, err := FromContext(ctx)
	if err != nil {
		return nil, err
	}
	var cops ChangeOps
	if !ec.DryRun {
		cops, err = ec.VCS.GetChangeOps(ctx)
		if err != nil {
			return nil, err
		}
	}
	certPath, err := change(ctx, cops)
	if err != nil {
		if cops != nil {
			cops.Destroy()
		}
		return nil, fmt.Errorf("failed to modify manifest textproto: %w", err)
	}

	var commit any
	if !ec.DryRun {
		var err error
		commit, err = cops.TryCommit(ctx)
		if err != nil {
			cops.Destroy()
			return nil, fmt.Errorf("failed to submit change: %w", err)
		}
	}
	output.Infof(ctx, "Submitted new endorsement as %v", commit)
	return ec.VCS.Result(commit, certPath), nil
}

// RetrySubmit runs f to attempt a submit transaction without merge conflict or service
// irregularity. Each attempt should use a fresh workspace to work from the most up-to-date source
// to both avoid a conflict and drop entries in the manifest due to a write-write data race.
func RetrySubmit(ctx context.Context, f func(context.Context, ChangeOps) (string, error)) (any, error) {
	ec, err := FromContext(ctx)
	if err != nil {
		return nil, err
	}
	var tries int
	for {
		resp, err := tryChange(ctx, f)
		if err != nil {
			output.Warningf(ctx, "Commit failed: %v", err)
			if ec.VCS.RetriableError(err) {
				tries++
				remain := ec.CommitRetries - tries
				// 1 try is 0 retries, so < 0 means there are no retries left.
				if remain < 0 {
					break
				}
				output.Debugf(ctx, "Warning: Retrying (%d retries left) submission", remain)
				continue
			}
			// Not retriable, so we're done.
			return nil, err
		}
		// No error, we're done.
		return resp, nil
	}
	return nil, ErrNoRetries
}

func commitEndorsement(ctx context.Context, endorsement *epb.VMLaunchEndorsement) (any, error) {
	output.Infof(ctx, "Starting endorsement submission.")
	resp, err := RetrySubmit(ctx, func(ctx context.Context, cops ChangeOps) (string, error) {
		return changeEndorsements(ctx, cops, endorsement)
	})
	if err != nil {
		return nil, err
	}

	output.Infof(ctx, "Endorsement submitted.")
	return resp, nil
}
