package host

import (
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/edutko/decipher/internal/file"
	"github.com/edutko/decipher/internal/names"
)

func Inspect(addr string) (file.Info, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		addr = net.JoinHostPort(addr, "443")
		host, _, err = net.SplitHostPort(addr)
		if err != nil {
			return file.Info{}, err
		}
	}

	info := file.Info{
		Description: addr,
	}

	ip, cs, err := connect(addr, host, 0, nil, nil)
	if err != nil {
		return info, err
	}

	info.Attributes = append(info.Attributes, file.Attribute{"IP address", ip.String()})
	info.Attributes = append(info.Attributes, file.Attribute{"Server name", cs.ServerName})

	var tlsVersions []string
	supportedTLSVersions := getSupportedTLSVersions(addr, host)
	for _, v := range supportedTLSVersions {
		tlsVersions = append(tlsVersions, tls.VersionName(v))
	}
	info.Attributes = append(info.Attributes, file.Attribute{"Protocol versions", strings.Join(tlsVersions, ", ")})
	info.Attributes = append(info.Attributes, file.Attribute{"Cipher suite", tls.CipherSuiteName(cs.CipherSuite)})

	groupMap := make(map[tls.CurveID]bool)
	if slices.Contains(supportedTLSVersions, tls.VersionTLS12) {
		for _, c := range getSupportedGroups(addr, host, tls.VersionTLS12) {
			groupMap[c] = true
		}
	}
	if slices.Contains(supportedTLSVersions, tls.VersionTLS13) {
		for _, c := range getSupportedGroups(addr, host, tls.VersionTLS13) {
			groupMap[c] = true
		}
	}
	var groupNames []string
	for id := range groupMap {
		groupNames = append(groupNames, groupName(id))
	}
	info.Attributes = append(info.Attributes, file.Attribute{"Key exchange groups", strings.Join(groupNames, ", ")})

	for _, cert := range cs.PeerCertificates {
		if certInfo, err := file.GetCertificateInfo(cert); err == nil {
			info.Children = append(info.Children, certInfo)
		}
	}

	return info, nil
}

func getSupportedTLSVersions(addr, host string) []uint16 {
	var supported []uint16

	// TODO: check for SSL 3.0
	for _, v := range []uint16{tls.VersionSSL30, tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
		_, _, err := connect(addr, host, v, nil, nil)
		if err == nil {
			supported = append(supported, v)
		}
	}

	return supported
}

func getSupportedGroups(addr, host string, tlsVersion uint16) []tls.CurveID {
	groups := allTLS12Curves()
	if tlsVersion == tls.VersionTLS13 {
		groups = allTLS13Groups()
	}

	var supported []tls.CurveID
	for _, id := range groups {
		_, _, err := connect(addr, host, tlsVersion, nil, []tls.CurveID{id})
		if err == nil {
			supported = append(supported, id)
		}
	}
	return supported
}

func connect(addr, host string, tlsVersion uint16, cipherSuites []uint16, curves []tls.CurveID) (net.Addr, tls.ConnectionState, error) {
	minTLSVersion := uint16(tls.VersionTLS10)
	maxTLSVersion := uint16(tls.VersionTLS13)
	if tlsVersion != 0 {
		minTLSVersion = tlsVersion
		maxTLSVersion = tlsVersion
	}

	if len(cipherSuites) == 0 {
		cipherSuites = allSuites()
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		CipherSuites:       cipherSuites,
		MinVersion:         minTLSVersion,
		MaxVersion:         maxTLSVersion,
		CurvePreferences:   curves,
	})
	if err != nil {
		return nil, tls.ConnectionState{}, err
	}
	defer conn.Close()

	return conn.RemoteAddr(), conn.ConnectionState(), nil
}

func allTLS12Curves() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}
}

func allTLS13Groups() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
		ffdhe2048,
		ffdhe3072,
		ffdhe4096,
		ffdhe6144,
		ffdhe8192,
		tls.SecP256r1MLKEM768,
		tls.X25519MLKEM768,
		tls.SecP384r1MLKEM1024,
		mlkem512,
		mlkem768,
		mlkem1024,
	}
}

func allSuites() []uint16 {
	var suites []uint16
	for _, s := range tls.InsecureCipherSuites() {
		suites = append(suites, s.ID)
	}
	for _, s := range tls.CipherSuites() {
		suites = append(suites, s.ID)
	}
	return suites
}

func groupName(id tls.CurveID) string {
	switch id {
	case tls.CurveP256:
		return names.Secp256r1
	case tls.CurveP384:
		return names.Secp384r1
	case tls.CurveP521:
		return names.Secp521r1
	case tls.X25519:
		return names.X25519
	case x448:
		return names.X448
	case ffdhe2048:
		return "ffdhe2048"
	case ffdhe3072:
		return "ffdhe3072"
	case ffdhe4096:
		return "ffdhe4096"
	case ffdhe6144:
		return "ffdhe6144"
	case ffdhe8192:
		return "ffdhe8192"
	case tls.SecP256r1MLKEM768:
		return "SECP256r1MLKEM768"
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.SecP384r1MLKEM1024:
		return "SECP384r1MLKEM1024"
	case mlkem512:
		return "MLKEM512"
	case mlkem768:
		return "MLKEM768"
	case mlkem1024:
		return "MLKEM1024"
	default:
		return fmt.Sprintf("unknown (%d)", id)
	}
}

const (
	x448 = tls.CurveID(30)

	ffdhe2048 = tls.CurveID(256)
	ffdhe3072 = tls.CurveID(257)
	ffdhe4096 = tls.CurveID(258)
	ffdhe6144 = tls.CurveID(259)
	ffdhe8192 = tls.CurveID(260)

	mlkem512  = tls.CurveID(512)
	mlkem768  = tls.CurveID(513)
	mlkem1024 = tls.CurveID(514)
)
