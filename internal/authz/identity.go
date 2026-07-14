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

import "context"

// Identity is the operator the manager derived from the presented client
// certificate (or the dev identity under AuthBypass).
type Identity struct {
	CN     string
	Serial string
	Level  Level
}

// DevIdentity is the identity injected in the AuthBypass dev path, where the
// browser cannot present an installed client cert over h2c.
var DevIdentity = Identity{CN: "operator@acme.example", Serial: "DEV", Level: LevelAdmin}

type identityCtxKey struct{}

// NewContext returns ctx carrying id.
func NewContext(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityCtxKey{}, id)
}

// FromContext returns the Identity carried by ctx, if any.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityCtxKey{}).(Identity)
	return id, ok
}
