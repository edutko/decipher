// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"unicode"
)

// This file contains tests derived from draft-ietf-tls-tls13-vectors-07.

func parseVector(v string) []byte {
	v = strings.Map(func(c rune) rune {
		if unicode.IsSpace(c) {
			return -1
		}
		return c
	}, v)
	parts := strings.Split(v, ":")
	v = parts[len(parts)-1]
	res, err := hex.DecodeString(v)
	if err != nil {
		panic(err)
	}
	return res
}

func TestTrafficKey(t *testing.T) {
	trafficSecret := parseVector(
		`PRK (32 octets):  b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4
		e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38`)
	wantKey := parseVector(
		`key expanded (16 octets):  3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e
		e4 03 bc`)
	wantIV := parseVector(
		`iv expanded (12 octets):  5d 31 3e b2 67 12 76 ee 13 00 0b 30`)

	c := cipherSuitesTLS13[0]
	gotKey, gotIV := c.trafficKey(trafficSecret)
	if !bytes.Equal(gotKey, wantKey) {
		t.Errorf("cipherSuiteTLS13.trafficKey() gotKey = % x, want % x", gotKey, wantKey)
	}
	if !bytes.Equal(gotIV, wantIV) {
		t.Errorf("cipherSuiteTLS13.trafficKey() gotIV = % x, want % x", gotIV, wantIV)
	}
}
