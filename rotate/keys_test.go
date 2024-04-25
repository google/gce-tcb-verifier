package rotate

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/google/gce-tcb-verifier/sign/memca"
	sops "github.com/google/gce-tcb-verifier/sign/ops"
	"github.com/google/gce-tcb-verifier/testing/match"
	"github.com/google/gce-tcb-verifier/testing/testsign"
)

func TestGoogleCertificateTemplate(t *testing.T) {
	ctx0 := context.Background()
	ca := memca.Create()
	time0 := time.Date(1999, time.July, 10, 12, 30, 0, 0, time.UTC)
	time1 := time.Date(2023, time.September, 25, 10, 15, 0, 0, time.UTC)
	time2 := time.Date(2021, time.October, 31, 23, 59, 0, 0, time.UTC)
	s, err := testsign.MakeSigner(ctx0, &testsign.Options{
		Now:               time0,
		Random:            testsign.RootRand(),
		CA:                ca,
		Root:              testsign.KeyInfo{CommonName: "rcn_source", KeyVersionName: "rkvn"},
		PrimarySigningKey: testsign.KeyInfo{CommonName: "scn_source", KeyVersionName: "pskvn"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rpub := s.Keys["rkvn"].Public()
	spub := s.Keys["pskvn"].Public()
	rootCert, err := sops.IssuerCertFromBundle(ctx0, ca, "rkvn")
	if err != nil {
		t.Fatal(err)
	}
	tcs := []struct {
		name              string
		ctx               context.Context
		issuer            *x509.Certificate
		pkey              any
		wantErr           string
		wantIssuerCn      string
		wantSubjectCn     string
		wantSubjectSerial string
		wantNotBefore     time.Time
	}{
		{
			name: "root bootstrap",
			ctx: NewBootstrapContext(ctx0, &BootstrapContext{
				RootKeyCommonName: "rcn",
				RootKeySerial:     big.NewInt(9),
				Now:               time1,
			}),
			wantSubjectCn:     "rcn",
			wantIssuerCn:      "rcn",
			pkey:              rpub,
			wantSubjectSerial: "9",
			wantNotBefore:     time1,
		},
		{
			name: "psk bootstrap",
			ctx: NewBootstrapContext(ctx0, &BootstrapContext{
				SigningKeyCommonName: "scn",
				SigningKeySerial:     big.NewInt(10),
				Now:                  time2,
			}),
			issuer:            rootCert,
			wantSubjectCn:     "scn",
			wantIssuerCn:      "rcn_source",
			pkey:              spub,
			wantSubjectSerial: "10",
			wantNotBefore:     time2,
		},
		{
			name: "psk rotate",
			ctx: NewSigningKeyContext(ctx0, &SigningKeyContext{
				SigningKeyCommonName: "scn",
				SigningKeySerial:     big.NewInt(10),
				Now:                  time1,
			}),
			issuer:            rootCert,
			wantSubjectCn:     "scn",
			wantIssuerCn:      "rcn_source",
			pkey:              spub,
			wantSubjectSerial: "10",
			wantNotBefore:     time1,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GoogleCertificateTemplate(tc.ctx, tc.issuer, tc.pkey)
			if !match.Error(err, tc.wantErr) {
				t.Fatalf("GoogleCertificateTemplate errored unexpectedly: %v, want %q", err, tc.wantErr)
			}
			if tc.wantErr == "" {
				if tc.wantIssuerCn != got.Issuer.CommonName {
					t.Errorf("issuer.CommonName = %q, want %q", got.Issuer.CommonName, tc.wantIssuerCn)
				}
				if tc.wantSubjectCn != got.Subject.CommonName {
					t.Errorf("subject.CommonName = %q, want %q", got.Subject.CommonName, tc.wantSubjectCn)
				}
				if got.Subject.SerialNumber != tc.wantSubjectSerial {
					t.Errorf("subject.SerialNumber = %q, want %q", got.Subject.SerialNumber, tc.wantSubjectSerial)
				}
				if !got.NotBefore.Equal(tc.wantNotBefore) {
					t.Errorf("NotBefore = %v, want %v", got.NotBefore, tc.wantNotBefore)
				}
			}
		})
	}
}
