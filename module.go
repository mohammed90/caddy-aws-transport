package awstransport

import (
	"fmt"
	"net/http"

	"github.com/BishopFox/aws-signing/signing"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

func init() {
	caddy.RegisterModule(new(AWSTransport))
}

type AWSTransport struct {
	Transport       *reverseproxy.HTTPTransport `json:"transport,omitempty"`
	AccessKeyID     string                      `json:"access_key_id,omitempty"`
	SecretAccessKey string                      `json:"secret_access_key,omitempty"`
	Region          string                      `json:"region,omitempty"`
	Service         string                      `json:"service,omitempty"`
}

// CaddyModule implements caddy.Module.
func (*AWSTransport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.reverse_proxy.transport.aws",
		New: func() caddy.Module {
			return new(AWSTransport)
		},
	}
}

// Provision implements caddy.Provisioner.
func (a *AWSTransport) Provision(ctx caddy.Context) error {
	if len(a.AccessKeyID) == 0 || len(a.SecretAccessKey) == 0 || len(a.Service) == 0 || len(a.Region) == 0 {
		return fmt.Errorf("some configuration values are missing")
	}
	if a.Transport == nil {
		a.Transport = new(reverseproxy.HTTPTransport)
	}
	err := a.Transport.Provision(ctx)
	if err != nil {
		return err
	}
	return nil
}

// EnableTLS implements reverseproxy.TLSTransport.
func (a *AWSTransport) EnableTLS(base *reverseproxy.TLSConfig) error {
	return a.Transport.EnableTLS(base)
}

// TLSEnabled implements reverseproxy.TLSTransport.
func (a *AWSTransport) TLSEnabled() bool {
	return a.Transport.TLSEnabled()
}

// RoundTrip implements http.RoundTripper.
func (a *AWSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	replacer := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	replacer.ReplaceKnown(a.Service, "")
	t := signing.NewTransport(
		v4.NewSigner(),
		aws.Credentials{
			AccessKeyID:     replacer.ReplaceKnown(a.AccessKeyID, ""),
			SecretAccessKey: replacer.ReplaceKnown(a.SecretAccessKey, ""),
		},
		replacer.ReplaceKnown(a.Service, ""),
		replacer.ReplaceKnown(a.Region, ""),
	)
	t.BaseTransport = a.Transport
	return t.RoundTrip(req)
}

func (a *AWSTransport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "access_id":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.AccessKeyID = d.Val()
			case "secret_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.SecretAccessKey = d.Val()
			case "region":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.Region = d.Val()
			case "service":
				if !d.NextArg() {
					return d.ArgErr()
				}
				a.Service = d.Val()
			case "transport":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if a.Transport != nil {
					return d.Err("backing transport is already specified")
				}
				a.Transport = new(reverseproxy.HTTPTransport)
				if err := a.Transport.UnmarshalCaddyfile(d); err != nil {
					return err
				}
			default:
				return d.Errf("unrecognized parameter '%s'", d.Val())
			}
		}
	}
	return nil
}

var (
	_ caddy.Module              = (*AWSTransport)(nil)
	_ caddy.Provisioner         = (*AWSTransport)(nil)
	_ http.RoundTripper         = (*AWSTransport)(nil)
	_ reverseproxy.TLSTransport = (*AWSTransport)(nil)
	_ caddyfile.Unmarshaler     = (*AWSTransport)(nil)
)
