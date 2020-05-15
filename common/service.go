package common

import "context"

// Service describes a service that can be started and stopped
type Service interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}
