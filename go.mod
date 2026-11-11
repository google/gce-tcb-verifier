module github.com/google/gce-tcb-verifier

go 1.26.2

require (
	cloud.google.com/go/iam v1.15.1
	cloud.google.com/go/kms v1.37.0
	github.com/cyphar/filepath-securejoin v0.7.0
	github.com/google/go-cmp v0.7.0
	github.com/google/go-configfs-tsm v0.3.3
	github.com/google/go-sev-guest v0.15.0
	github.com/google/go-tdx-guest v0.3.2-0.20250814004405-ffb0869e6f4d
	github.com/google/go-tpm-tools v0.4.11
	github.com/google/logger v1.1.2
	github.com/google/uuid v1.6.0
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.10.2
	go.uber.org/multierr v1.11.0
	golang.org/x/exp v0.0.0-20261109185158-a52e3aef5920
	golang.org/x/text v0.44.0
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
)

require (
	cloud.google.com/go/longrunning v1.5.0 // indirect
	github.com/GoogleCloudPlatform/confidential-space/server v0.0.0-20261111061945-c34bbc5727b5 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.1.0 // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	google.golang.org/genproto v0.0.0-20261110000943-09e21b237f2c // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261110000943-09e21b237f2c // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261110000943-09e21b237f2c // indirect
)
