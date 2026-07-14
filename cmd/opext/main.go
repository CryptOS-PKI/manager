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
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/CryptOS-PKI/manager/internal/authz"
)

// run encodes the access-level extension value for the given level token and
// writes its base64 (for pasting into a cryptos profile's extra_extensions
// value) to w.
func run(level string, w io.Writer) error {
	l, err := authz.LevelFromToken(level)
	if err != nil {
		return err
	}
	value, err := authz.MarshalLevelValue(l)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, base64.StdEncoding.EncodeToString(value))
	return err
}

func main() {
	level := flag.String("level", "", "access level: viewer|operator|admin")
	flag.Parse()
	if err := run(*level, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "opext:", err)
		os.Exit(1)
	}
}
