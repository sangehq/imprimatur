package execx

import (
	"fmt"
	"slices"
	"strings"
)

// The .p12 re-wrap on macOS (backend/apple.go) runs openssl in two forms and
// no others. The real .p12 password reaches openssl only through the
// environment variable P12InEnv, never on a command line; the re-wrapped file
// is protected by a random one-time password, read from P12OutEnv.
const (
	P12InEnv  = "IMPR_P12_IN"
	P12OutEnv = "IMPR_P12_OUT"
)

// opensslDecrypt is: pkcs12 -in P12 -nodes -passin env:IMPR_P12_IN -out PEM [-legacy]
// opensslExport is: pkcs12 -export -in PEM -out P12 -passout env:IMPR_P12_OUT
// -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 (what macOS's
// security import reliably accepts).
func checkOpenSSL(args []string) error {
	refuse := func() error {
		return fmt.Errorf("openssl %s: %w (only the .p12 re-wrap forms)", strings.Join(args, " "), ErrNotAllowed)
	}
	paths := func(vs ...string) bool {
		for _, v := range vs {
			if v == "" || strings.HasPrefix(v, "-") {
				return false
			}
		}
		return true
	}
	switch {
	case len(args) >= 8 && args[0] == "pkcs12" && args[1] == "-in" && args[3] == "-nodes" && args[4] == "-passin" &&
		args[5] == "env:"+P12InEnv && args[6] == "-out":
		legacyOK := len(args) == 8 || (len(args) == 9 && args[8] == "-legacy")
		if !paths(args[2], args[7]) || !legacyOK {
			return refuse()
		}
		return nil
	case len(args) == 14 && slices.Equal([]string{args[0], args[1], args[2], args[4], args[6], args[7]},
		[]string{"pkcs12", "-export", "-in", "-out", "-passout", "env:" + P12OutEnv}) &&
		slices.Equal(args[8:], []string{"-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1"}):
		if !paths(args[3], args[5]) {
			return refuse()
		}
		return nil
	}
	return refuse()
}
