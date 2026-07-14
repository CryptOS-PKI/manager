package main

/*
Apache License 2.0

Copyright 2026 Shane

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"testing"
)

func TestRun_PrintsBase64DERForLevel(t *testing.T) {
	var out bytes.Buffer
	if err := run("admin", &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(out.Bytes())))
	if err != nil {
		t.Fatalf("output not base64: %v", err)
	}
	var token string
	if _, err := asn1.Unmarshal(der, &token); err != nil || token != "admin" {
		t.Fatalf("decoded %q err %v; want admin", token, err)
	}
}

func TestRun_RejectsUnknownLevel(t *testing.T) {
	var out bytes.Buffer
	if err := run("root", &out); err == nil {
		t.Error("run(root) = nil error, want error")
	}
}
