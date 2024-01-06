package awstransport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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

// The AWS transport module injects the AWS V4 Signature for requests proxied to AWS services.
// It also implicitly calculates and sets the `x-amz-content-sha256` header value.
type AWSTransport struct {
	*reverseproxy.HTTPTransport `json:"transport,omitempty"`

	// One part of the AWS security credentials identifying the service user
	AccessKeyID string `json:"access_key_id,omitempty"`

	// The other part of the AWS security credentials
	SecretAccessKey string `json:"secret_access_key,omitempty"`

	// The AWS region, e.g. us-east-2
	Region string `json:"region,omitempty"`

	// The upstream AWS service
	Service string `json:"service,omitempty"`
}

// CaddyModule implements caddy.Module.
func (*AWSTransport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.reverse_proxy.transport.aws",
		New: func() caddy.Module {
			m := new(AWSTransport)
			m.HTTPTransport = new(reverseproxy.HTTPTransport)
			return m
		},
	}
}

// Provision implements caddy.Provisioner.
func (a *AWSTransport) Provision(ctx caddy.Context) error {
	if len(a.AccessKeyID) == 0 || len(a.SecretAccessKey) == 0 || len(a.Service) == 0 || len(a.Region) == 0 {
		return fmt.Errorf("some configuration values are missing")
	}
	if a.HTTPTransport == nil {
		a.HTTPTransport = new(reverseproxy.HTTPTransport)
	}
	return a.HTTPTransport.Provision(ctx)
}

// RoundTrip implements http.RoundTripper.
func (a *AWSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	hash, err := hashPayload(req)
	if err != nil {
		return nil, fmt.Errorf("error hashing payload: %s", err)
	}
	req.Header.Set("x-amz-content-sha256", hash)

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
	t.BaseTransport = a.HTTPTransport
	return t.RoundTrip(req)
}

func hashPayload(req *http.Request) (string, error) {
	var sum [32]byte
	if req.Body == nil {
		sum = sha256.Sum256(nil)
	} else {
		d, err := io.ReadAll(req.Body)
		if err != nil {
			return "", fmt.Errorf("error reading http body to sign: %s", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(d))
		sum = sha256.Sum256(d)
	}
	return hex.EncodeToString(sum[:]), nil
}

func (a *AWSTransport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	for d.NextBlock(0) {
		switch d.Val() {
		case "access_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.AccessKeyID = d.Val()
			d.DeleteN(2)
		case "secret_key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.SecretAccessKey = d.Val()
			d.DeleteN(2)
		case "region":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.Region = d.Val()
			d.DeleteN(2)
		case "service":
			if !d.NextArg() {
				return d.ArgErr()
			}
			a.Service = d.Val()
			d.DeleteN(2)
		}
	}
	d.Reset()
	return (a.HTTPTransport).UnmarshalCaddyfile(d)
}

var (
	_ caddy.Module              = (*AWSTransport)(nil)
	_ caddy.Provisioner         = (*AWSTransport)(nil)
	_ http.RoundTripper         = (*AWSTransport)(nil)
	_ reverseproxy.TLSTransport = (*AWSTransport)(nil)
	_ caddyfile.Unmarshaler     = (*AWSTransport)(nil)
)
