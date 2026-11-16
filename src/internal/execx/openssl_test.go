package execx

import (
	"errors"
	"testing"
)

func TestOpenSSLOnlyTheRewrapForms(t *testing.T) {
	decrypt := []string{"pkcs12", "-in", "/t/id.p12", "-nodes", "-passin", "env:IMPR_P12_IN", "-out", "/t/identity.pem"}
	export := []string{"pkcs12", "-export", "-in", "/t/identity.pem", "-out", "/t/identity.p12", "-passout", "env:IMPR_P12_OUT",
		"-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1"}
	for _, ok := range [][]string{decrypt, append(append([]string{}, decrypt...), "-legacy"), export} {
		if err := Check(Cmd{Tool: "openssl", Args: ok}); err != nil {
			t.Fatalf("%v refused: %v", ok, err)
		}
	}
	bad := map[string][]string{
		"password on the command line": {"pkcs12", "-in", "/t/id.p12", "-nodes", "-passin", "pass:hunter2", "-out", "/t/identity.pem"},
		"another variable":             {"pkcs12", "-in", "/t/id.p12", "-nodes", "-passin", "env:HOME", "-out", "/t/identity.pem"},
		"another subcommand":           {"s_client", "-connect", "example.com:443"},
		"an option as a path":          {"pkcs12", "-in", "-engine", "-nodes", "-passin", "env:IMPR_P12_IN", "-out", "/t/identity.pem"},
		"modern export":                append(append([]string{}, export[:8]...), "-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC", "-macalg", "sha256"),
		"extra argument":               append(append([]string{}, decrypt...), "-engine", "x"),
	}
	for name, args := range bad {
		if err := Check(Cmd{Tool: "openssl", Args: args}); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: want refused, got %v", name, err)
		}
	}
}
