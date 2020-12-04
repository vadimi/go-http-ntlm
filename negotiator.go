package httpntlm

import (
	"encoding/base64"
	"encoding/binary"
)

const (
	negotiateUnicode                 = 0x0001     // Text strings are in unicode
	negotiateOEM                     = 0x0002     // Text strings are in OEM
	requestTarget                    = 0x0004     // Server return its auth realm
	negotiateSign                    = 0x0010     // Request signature capability
	negotiateSeal                    = 0x0020     // Request confidentiality
	negotiateLMKey                   = 0x0080     // Generate session key
	negotiateNTLM                    = 0x0200     // NTLM authentication
	negotiateLocalCall               = 0x4000     // client/server on same machine
	negotiateAlwaysSign              = 0x8000     // Sign for all security levels
	negotiateExtendedSessionSecurity = 0x80000    // Extended session security
	negotiateVersion                 = 0x02000000 // negotiate version flag
	negotiate128                     = 0x20000000 // 128-bit session key negotiation
	negotiateKeyExch                 = 0x40000000 // Key exchange
	negotiate56                      = 0x80000000 // 56-bit encryption
)

var (
	put32     = binary.LittleEndian.PutUint32
	put16     = binary.LittleEndian.PutUint16
	encBase64 = base64.StdEncoding.EncodeToString
	decBase64 = base64.StdEncoding.DecodeString
)

// generates NTLM Negotiate type-1 message
// for details see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2
func negotiate() []byte {
	ret := make([]byte, 40)
	flags := negotiateAlwaysSign | negotiateExtendedSessionSecurity | negotiateKeyExch | negotiate128 | negotiate56 | negotiateNTLM | requestTarget | negotiateOEM | negotiateUnicode | negotiateVersion

	copy(ret, []byte("NTLMSSP\x00")) // protocol
	put32(ret[8:], 1)                // type
	put32(ret[12:], uint32(flags))   // flags
	put16(ret[16:], 0)               // NT domain name length
	put16(ret[18:], 0)               // NT domain name max length
	put32(ret[20:], 0)               // NT domain name offset
	put16(ret[24:], 0)               // local workstation name length
	put16(ret[26:], 0)               // local workstation name max length
	put32(ret[28:], 40)              // local workstation name offset
	put16(ret[32:], 0x0106)          // ProductMajorVersion - 6, ProductMinorVersion - 1
	put16(ret[34:], 7601)            // ProductBuild - 7601
	put16(ret[38:], 0x0f00)          // NTLM revision - 15

	return ret
}
