AWS Transport for Caddy
======

> [!NOTE]
> The module is not validated -- yet! I don't use AWS personally, so feedback is welcome. Consider it WIP until this is removed.
> The configuration structure is also subject to change.

This module aims to injects the AWS V4 Signature for requests proxied to AWS services.


## Example

### Caddyfile

```caddyfile
example.com {
	reverse_proxy some-endpoint.awsservice.com {
		header_up Host {upstream_hostport}
		transport aws {
			access_id $AWS_ACCECSS_ID
			secret_key $AWS_SECRET_KEY
			region $AWS_REGION
			service $AWS_SERVICE

			# other 'http' transport directives per:
			# https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#the-http-transport 
		}
	}
}
```

