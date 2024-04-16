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

// Package output provides operations for command implementations to write information of various
// kinds.
package output

import (
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"io"
	"os"

	"github.com/google/logger"
	"github.com/spf13/cobra"
)

var (
	// ErrNoContext is returned when FromContext cannot find an output.Options in the context.
	ErrNoContext = errors.New("no output context found")

	stdoutTty      *typeWriter
	stderrTty      *typeWriter
	alwaysErrorTty *typeWriter
	discardTty     *typeWriter
)

const (
	warningPrefix = "WARNING: "
	errorPrefix   = "ERROR: "
	debugPrefix   = "DEBUG: "
)

// Options controls the meaning of output modalities.
type Options struct {
	Quiet     bool
	Verbose   bool
	UseLogs   bool
	Overwrite bool
	KeepGoing bool
	Out       io.Writer
	Err       io.Writer
}

// AddFlags adds flags specific to the Options object to the given command.
func (opts *Options) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().BoolVar(&opts.Quiet, "quiet", false,
		"Print nothing if command is successful")
	cmd.PersistentFlags().BoolVar(&opts.Verbose, "verbose", false,
		"Print additional info to stdout")
	cmd.PersistentFlags().BoolVar(&opts.UseLogs, "use_logs", false,
		"Print messages to log instead of stdout/stderr")
	cmd.PersistentFlags().BoolVar(&opts.Overwrite, "overwrite", false,
		"Allow write operations to overwrite existing files and continue without error for existing keys.")
	cmd.PersistentFlags().BoolVar(&opts.KeepGoing, "keep_going", false,
		"If true, then if multiple operations happen in sequence from a command and any one fails, "+
			"keep going as long as there's no direct dependency.")
}

// Validate returns an error if the Options values are incompatible.
func (opts *Options) Validate(cmd *cobra.Command) error {
	if opts.Quiet && opts.Verbose {
		return fmt.Errorf("cannot specify both --quiet and --verbose")
	}
	cmd.SilenceUsage = true
	return nil
}

type outputKeyType struct{}

var outputKey outputKeyType

// NewContext returns ctx extended with opts added.
func NewContext(ctx context.Context, opts *Options) context.Context {
	return context.WithValue(ctx, outputKey, opts)
}

// FromContext returns the Options value in ctx if it exists.
func FromContext(ctx context.Context) (*Options, error) {
	opts, ok := ctx.Value(outputKey).(*Options)
	if !ok {
		return nil, ErrNoContext
	}
	return opts, nil
}

type typeWriter struct {
	w     io.Writer
	istty bool
}

type statWriter interface {
	Write(p []byte) (n int, err error)
	Stat() (os.FileInfo, error)
}

func isTty(w statWriter) bool {
	s, err := w.Stat()
	return err == nil && s != nil && (s.Mode()&os.ModeCharDevice) == os.ModeCharDevice
}

func init() {
	stdoutTty = &typeWriter{w: os.Stdout, istty: isTty(os.Stdout)}
	stderrTty = &typeWriter{w: os.Stderr, istty: isTty(os.Stderr)}
	alwaysErrorTty = &typeWriter{w: &alwaysError{}, istty: false}
	discardTty = &typeWriter{w: &discard{}, istty: false}
}

// alwaysError implements io.ReadWriter by always returning an error
type alwaysError struct {
	error
}

func (ae alwaysError) Write([]byte) (int, error) {
	return 0, ae.error
}

func (ae alwaysError) Read(_ []byte) (n int, err error) {
	return 0, ae.error
}

func (ae alwaysError) Stat() (os.FileInfo, error) {
	return nil, ae.error
}

type discard struct{}

func (*discard) Write(_ []byte) (n int, err error) {
	return 0, nil
}

// Output is a sink for standard tool output.
func output(ctx context.Context) *typeWriter {
	opts, err := FromContext(ctx)
	if err != nil {
		return alwaysErrorTty
	}
	if opts.UseLogs {
		return nil
	}
	if opts.Quiet {
		return discardTty
	}
	if opts.Out != nil {
		return &typeWriter{w: opts.Out, istty: false}
	}
	return stdoutTty
}

// Debug is a verbose sink for tool output.
func debug(ctx context.Context) *typeWriter {
	opts, err := FromContext(ctx)
	if err != nil {
		return alwaysErrorTty
	}
	if opts.UseLogs {
		return nil
	}
	if opts.Verbose {
		return stdoutTty
	}
	if opts.Err != nil {
		return &typeWriter{w: opts.Err, istty: false}
	}
	return discardTty
}

type ansiColor int

const (
	red    ansiColor = 31
	yellow ansiColor = 33
)

// https://en.wikipedia.org/wiki/ANSI_escape_code
func boldColor(colorCode ansiColor, txt string) string {
	return fmt.Sprintf("\033[1;%dm%s\033[0m", colorCode, txt)
}

func fancyText(w *typeWriter, color ansiColor, txt string) string {
	if w.istty {
		return boldColor(color, txt)
	}
	return txt
}

func warningTxt(ctx context.Context) string {
	return fancyText(output(ctx), yellow, warningPrefix)
}

func errorTxt(ctx context.Context) string {
	return fancyText(output(ctx), red, errorPrefix)
}

// Infof writes a formatted string with a newline to the Output modality.
func Infof(ctx context.Context, format string, args ...any) (int, error) {
	if cw := output(ctx); cw != nil {
		return fmt.Fprintf(output(ctx).w, format+"\n", args...)
	}
	logger.Infof(format, args...)
	return 1, nil
}

// AllowOverwrite returns true if --overwrite is true.
func AllowOverwrite(ctx context.Context) bool {
	o, _ := FromContext(ctx)
	return o != nil && o.Overwrite
}

// AllowRecoverableError returns true if --keep_going is true.
func AllowRecoverableError(ctx context.Context) bool {
	o, _ := FromContext(ctx)
	return o != nil && o.KeepGoing
}

// Warningf writes a formatted string with a newline to the Output modality, prefixed by a warning
// message.
func Warningf(ctx context.Context, format string, args ...any) (int, error) {
	if cw := output(ctx); cw != nil {
		return fmt.Fprintf(output(ctx).w, warningTxt(ctx)+format+"\n", args...)
	}
	logger.Warningf(format, args...)
	return 1, nil
}

// Errorf writes a formatted string with a newline to the Output modality, prefixed by an error
// message.
func Errorf(ctx context.Context, format string, args ...any) (int, error) {
	if cw := output(ctx); cw != nil {
		return fmt.Fprintf(cw.w, errorTxt(ctx)+format+"\n", args...)
	}
	logger.Errorf(format, args...)
	return 1, nil
}

// In OSS, there is no Boolean condition for whether a particular verbosity level is active, so this
// type uses delayed string rendering to determine if logging occurred.
type onRender struct{ wasRendered bool }

func (o *onRender) String() string {
	o.wasRendered = true
	return ""
}

// Debugf writes a formatted string with a newline to the Debug modality.
func Debugf(ctx context.Context, format string, args ...any) (int, error) {
	if cw := debug(ctx); cw != nil {
		return fmt.Fprintf(cw.w, debugPrefix+format+"\n", args...)
	}
	var w onRender
	logger.V(1).Infof(format+"%v", append(args, &w))
	if w.wasRendered {
		return 1, nil
	}
	return 0, nil
}
