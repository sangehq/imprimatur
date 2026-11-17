package backend

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// O-176: AppLocker names a publisher by O, L, S and C, upper-cased, with the
// CN left out (the PowerShell toolkit's Get-AppLockerPublisher, and what
// Get-AppLockerFileInformation reports). A subject with none of them falls
// back to the CN.
func TestAppLockerPublisherName(t *testing.T) {
	for _, c := range []struct {
		name pkix.Name
		want string
	}{
		{pkix.Name{CommonName: "Acme Ltd", Organization: []string{"Acme Ltd"}, Locality: []string{"London"}, Country: []string{"GB"}},
			"O=ACME LTD, L=LONDON, C=GB"},
		{pkix.Name{CommonName: "Microsoft Corporation", Organization: []string{"Microsoft Corporation"}, Locality: []string{"Redmond"},
			Province: []string{"Washington"}, Country: []string{"US"}}, "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"},
		{pkix.Name{CommonName: "Acme, Inc.", Organization: []string{"Acme, Inc."}, Country: []string{"US"}}, `O="ACME, INC.", C=US`},
		{pkix.Name{CommonName: "Imani Code Signing (Test)"}, "CN=IMANI CODE SIGNING (TEST)"},
	} {
		raw, err := asn1.Marshal(c.name.ToRDNSequence())
		if err != nil {
			t.Fatal(err)
		}
		if got := AppLockerPublisher(raw); got != c.want {
			t.Errorf("%v: got %q, want %q", c.name, got, c.want)
		}
	}
}
