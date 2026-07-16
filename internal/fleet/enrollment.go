package fleet

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

	connect "connectrpc.com/connect"
	fleetv1 "github.com/CryptOS-PKI/api/go/cryptos/fleet/v1"
)

// TODO(enrollment Task 7): implement. Stubbed to satisfy the handler interface.
func (s *Service) CreateEnrollment(context.Context, *connect.Request[fleetv1.CreateEnrollmentRequest]) (*connect.Response[fleetv1.CreateEnrollmentResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("fleet: CreateEnrollment not yet implemented"))
}

// TODO(enrollment Task 7): implement. Stubbed to satisfy the handler interface.
func (s *Service) ApproveEnrollment(context.Context, *connect.Request[fleetv1.ApproveEnrollmentRequest]) (*connect.Response[fleetv1.ApproveEnrollmentResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("fleet: ApproveEnrollment not yet implemented"))
}

// TODO(enrollment Task 7): implement. Stubbed to satisfy the handler interface.
func (s *Service) RejectEnrollment(context.Context, *connect.Request[fleetv1.RejectEnrollmentRequest]) (*connect.Response[fleetv1.RejectEnrollmentResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("fleet: RejectEnrollment not yet implemented"))
}
