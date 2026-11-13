package paseto_test

import (
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/stretchr/testify/require"
)

// conflictingClaimsVectors are claims JSON payloads containing duplicate
// top-level keys. encoding/json would silently collapse these (keeping the
// last value), so parsers must reject them outright instead.
var conflictingClaimsVectors = []struct {
	name   string
	claims string
}{
	{"duplicate aud", `{"aud":"attacker","sub":"user","exp":"2099-01-01T00:00:00Z","aud":"victim"}`},
	{"duplicate sub", `{"sub":"attacker","aud":"victim","exp":"2099-01-01T00:00:00Z","sub":"admin"}`},
	{"duplicate exp", `{"exp":"2020-01-01T00:00:00Z","aud":"victim","sub":"user","exp":"2099-01-01T00:00:00Z"}`},
	{"duplicate custom claim", `{"aud":"victim","exp":"2099-01-01T00:00:00Z","role":"user","role":"admin"}`},
}

var implicitAssertion = []byte("implicit")

type protocolKeys struct {
	v2Symmetric paseto.V2SymmetricKey
	v2Secret    paseto.V2AsymmetricSecretKey
	v3Symmetric paseto.V3SymmetricKey
	v3Secret    paseto.V3AsymmetricSecretKey
	v4Symmetric paseto.V4SymmetricKey
	v4Secret    paseto.V4AsymmetricSecretKey
}

func newProtocolKeys() protocolKeys {
	return protocolKeys{
		v2Symmetric: paseto.NewV2SymmetricKey(),
		v2Secret:    paseto.NewV2AsymmetricSecretKey(),
		v3Symmetric: paseto.NewV3SymmetricKey(),
		v3Secret:    paseto.NewV3AsymmetricSecretKey(),
		v4Symmetric: paseto.NewV4SymmetricKey(),
		v4Secret:    paseto.NewV4AsymmetricSecretKey(),
	}
}

func (k protocolKeys) signOrEncrypt(name string, packet paseto.Packet) string {
	switch name {
	case "v2.local":
		return paseto.V2LocalEncrypt(packet, k.v2Symmetric, nil).Encoded()
	case "v2.public":
		return paseto.V2PublicSign(packet, k.v2Secret).Encoded()
	case "v3.local":
		return paseto.V3LocalEncrypt(packet, k.v3Symmetric, implicitAssertion, nil).Encoded()
	case "v3.public":
		return paseto.V3PublicSign(packet, k.v3Secret, implicitAssertion).Encoded()
	case "v4.local":
		return paseto.V4LocalEncrypt(packet, k.v4Symmetric, implicitAssertion, nil).Encoded()
	case "v4.public":
		return paseto.V4PublicSign(packet, k.v4Secret, implicitAssertion).Encoded()
	default:
		panic("unknown protocol: " + name)
	}
}

func (k protocolKeys) parse(parser paseto.Parser, name string, token string) (*paseto.Token, error) {
	switch name {
	case "v2.local":
		return parser.ParseV2Local(k.v2Symmetric, token)
	case "v2.public":
		return parser.ParseV2Public(k.v2Secret.Public(), token)
	case "v3.local":
		return parser.ParseV3Local(k.v3Symmetric, token, implicitAssertion)
	case "v3.public":
		return parser.ParseV3Public(k.v3Secret.Public(), token, implicitAssertion)
	case "v4.local":
		return parser.ParseV4Local(k.v4Symmetric, token, implicitAssertion)
	case "v4.public":
		return parser.ParseV4Public(k.v4Secret.Public(), token, implicitAssertion)
	default:
		panic("unknown protocol: " + name)
	}
}

var allProtocols = []string{
	"v2.local", "v2.public",
	"v3.local", "v3.public",
	"v4.local", "v4.public",
}

func TestParserRejectsConflictingClaims(t *testing.T) {
	keys := newProtocolKeys()
	parser := paseto.NewParserWithoutExpiryCheck()

	for _, vector := range conflictingClaimsVectors {
		t.Run(vector.name, func(t *testing.T) {
			packet := paseto.NewPacket([]byte(vector.claims), []byte("footer"))

			for _, protocol := range allProtocols {
				t.Run(protocol, func(t *testing.T) {
					token := keys.signOrEncrypt(protocol, packet)

					parsed, err := keys.parse(parser, protocol, token)
					require.Error(t, err)
					require.Nil(t, parsed)
					require.ErrorIs(t, err, paseto.TokenError{})
					require.NotErrorIs(t, err, paseto.RuleError{})
					require.ErrorContains(t, err, "duplicate")
				})
			}
		})
	}
}

func TestParserAcceptsConsistentClaims(t *testing.T) {
	keys := newProtocolKeys()

	parser := paseto.NewParser()
	parser.AddRule(paseto.ForAudience("victim"), paseto.Subject("user"))

	claims := `{"aud":"victim","sub":"user","exp":"2099-01-01T00:00:00Z","nested":{"role":"user","role":"admin"}}`
	footer := []byte("footer")
	packet := paseto.NewPacket([]byte(claims), footer)

	for _, protocol := range allProtocols {
		t.Run(protocol, func(t *testing.T) {
			token := keys.signOrEncrypt(protocol, packet)

			parsed, err := keys.parse(parser, protocol, token)
			require.NoError(t, err)
			require.Equal(t, footer, parsed.Footer())

			exp, err := parsed.GetExpiration()
			require.NoError(t, err)
			require.True(t, exp.Equal(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)))
		})
	}
}
