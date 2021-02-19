// +build darwin,cgo

package osxkeychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"
import "github.com/keybase/go-keychain"

// Protocols used to covert protocol to kSecAttrProtocol
var Protocols = map[string]string{
	"https": CFStringToString(C.CFStringRef(C.kSecAttrProtocolHTTPS)),
	"http":  CFStringToString(C.CFStringRef(C.kSecAttrProtocolHTTP)),
	"smtp":  CFStringToString(C.CFStringRef(C.kSecAttrProtocolSMTP)),
	"pop3":  CFStringToString(C.CFStringRef(C.kSecAttrProtocolPOP3)),
	"pop3s": CFStringToString(C.CFStringRef(C.kSecAttrProtocolPOP3S)),
	"socks": CFStringToString(C.CFStringRef(C.kSecAttrProtocolSOCKS)),
	"imap":  CFStringToString(C.CFStringRef(C.kSecAttrProtocolIMAP)),
	"imaps": CFStringToString(C.CFStringRef(C.kSecAttrProtocolIMAPS)),
	"ldap":  CFStringToString(C.CFStringRef(C.kSecAttrProtocolLDAP)),
	"ldaps": CFStringToString(C.CFStringRef(C.kSecAttrProtocolLDAPS)),
	"ssh":   CFStringToString(C.CFStringRef(C.kSecAttrProtocolSSH)),
	"ftp":   CFStringToString(C.CFStringRef(C.kSecAttrProtocolFTP)),
	"ftps":  CFStringToString(C.CFStringRef(C.kSecAttrProtocolFTPS)),
}

var (
	// ServerKey is for kSecAttrServer
	ServerKey = attrKey(C.CFTypeRef(C.kSecAttrServer))
	// ProtocolKey is for kSecAttrProtocol
	ProtocolKey = attrKey(C.CFTypeRef(C.kSecAttrProtocol))
	// PortKey is for kSecAttrPort
	PortKey = attrKey(C.CFTypeRef(C.kSecAttrPort))
	// PathKey is for kSecAttrPath
	PathKey = attrKey(C.CFTypeRef(C.kSecAttrPath))
)

// SetPath sets the Path attribute
func SetPath(k keychain.Item, s string) {
	k.SetString(PathKey, s)
}

// SetPort sets the Port attribute
func SetPort(k keychain.Item, s string) {
	k.SetString(PortKey, s)
}

// SetProtocol sets the Protocol attribute
func SetProtocol(k keychain.Item, s string) {
	k.SetString(ProtocolKey, Protocols[s])
}

// SetServer sets the server attribute
func SetServer(k keychain.Item, s string) {
	k.SetString(ServerKey, s)
}

func attrKey(ref C.CFTypeRef) string {
	return CFStringToString(C.CFStringRef(ref))
}

// CFStringToString converts a CFStringRef to a string.
func CFStringToString(s C.CFStringRef) string {
	p := C.CFStringGetCStringPtr(s, C.kCFStringEncodingUTF8)
	if p != nil {
		return C.GoString(p)
	}
	length := C.CFStringGetLength(s)
	if length == 0 {
		return ""
	}
	maxBufLen := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8)
	if maxBufLen == 0 {
		return ""
	}
	buf := make([]byte, maxBufLen)
	var usedBufLen C.CFIndex
	_ = C.CFStringGetBytes(s, C.CFRange{0, length}, C.kCFStringEncodingUTF8, C.UInt8(0), C.false, (*C.UInt8)(&buf[0]), maxBufLen, &usedBufLen)
	return string(buf[:usedBufLen])
}
