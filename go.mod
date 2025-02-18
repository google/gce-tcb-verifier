module github.com/google/gce-tcb-verifier

go 1.20

require (
	cloud.google.com/go/iam v1.1.6
	cloud.google.com/go/kms v1.15.7
	github.com/cyphar/filepath-securejoin v0.2.5
	github.com/google/go-cmp v0.6.0
	github.com/google/go-configfs-tsm v0.2.2
	github.com/google/go-sev-guest v0.11.2-0.20241017023127-f94d851ddd48
	github.com/google/go-tdx-guest v0.3.1
	github.com/google/go-tpm-tools v0.4.4
	github.com/google/logger v1.1.1
	github.com/google/uuid v1.6.0
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.8.0
	go.uber.org/multierr v1.11.0
	golang.org/x/exp v0.0.0-20240409090435-93d18d7e34b8
	golang.org/x/text v0.21.0
	google.golang.org/grpc v1.63.2
	google.golang.org/protobuf v1.33.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	google.golang.org/genproto v0.0.0-20240227224415-6ceb2ff114de // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240227224415-6ceb2ff114de // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240227224415-6ceb2ff114de // indirect
)
