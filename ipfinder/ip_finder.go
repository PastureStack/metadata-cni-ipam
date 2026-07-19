package ipfinder

import (
	"context"
	"net"
)

type IPFinder interface {
	FindIP(context.Context, string, string) (net.IP, error)
}
