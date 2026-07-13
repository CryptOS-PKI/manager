package authz

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
	"context"
	"errors"
	"testing"

	connect "connectrpc.com/connect"
)

// TestBypass_CallsNextAndReturnsResponseUnchanged asserts that the bypass
// interceptor is a pure pass-through: it invokes next exactly once and
// returns whatever next returns, unmodified.
func TestBypass_CallsNextAndReturnsResponseUnchanged(t *testing.T) {
	want := connect.NewResponse(&struct{ Marker string }{Marker: "next-was-called"})

	var calls int
	next := connect.UnaryFunc(func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		calls++

		return want, nil
	})

	interceptor := Bypass()
	wrapped := interceptor.WrapUnary(next)

	got, err := wrapped(context.Background(), nil)
	if err != nil {
		t.Fatalf("wrapped() error = %v, want nil", err)
	}
	if calls != 1 {
		t.Fatalf("next called %d times, want 1", calls)
	}
	if got != want {
		t.Fatalf("wrapped() response = %#v, want the exact response returned by next", got)
	}
}

// TestBypass_PropagatesNextError asserts that an error from next is
// returned unchanged, not swallowed or wrapped.
func TestBypass_PropagatesNextError(t *testing.T) {
	wantErr := connect.NewError(connect.CodeUnavailable, errors.New("node unreachable"))

	next := connect.UnaryFunc(func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, wantErr
	})

	interceptor := Bypass()
	wrapped := interceptor.WrapUnary(next)

	_, err := wrapped(context.Background(), nil)
	if err != wantErr {
		t.Fatalf("wrapped() error = %v, want %v", err, wantErr)
	}
}
