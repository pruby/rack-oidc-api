== Rack OIDC API Middleware ==

This is a small middleware layer to check for a JWT token issued to a particular audience by a particular OIDC provider. It can be used to create backing APIs for Single-Page Applications that use the OIDC implicit flow. Keys are loaded from the OIDC provider's discovery endpoint and JWKS store, rather than being hard-coded. The middleware can then validate bearer tokens on requests using the ruby-jwt library.

To use this in a Rack application, use like this:

    require 'rack-oidc-api/middleware'
    use RackOidcApi::Middleware, provider: 'https://provider.example.com', audience: 'my-client-id'

All requests that don't have a valid Bearer JWT token issued by that provider, to that audience will result in a 401. Audience validation is not optional. As this is meant for simple cases, it doesn't have any mechanism to except paths (all requests must have a valid token).

All auth will fail if the provider is unavailable at startup. If the provider disappears once the app is running, it keeps using the last keys retrieved until the provider comes back up again.

The validated JWT token is added to the Rack environment under the key :identity_token for use in any further validation (e.g. enforcing required claims). This is a ruby-jwt JWT object.

The following constraints apply:

  * Only supports RSA public key tokens (RS256, RS384, RS512).
  * Only supports loading the JWKS from the same origin (scheme, host, port) as the OIDC discovery endpoint.
  * Very little configuration is available or required.
  * Leeway for not-before and not-after constraints is fixed at 30 seconds.
  * It can't validate claims or scopes, as the encoding of these is too variable. This should be done in downstream middleware or your application.

I got the "how to middleware" from, and it borrows some code pieces from rack-jwt by eparenno ( https://github.com/eparreno/rack-jwt ).
