Gem::Specification.new do |s|
  s.name = %q{rack-oidc-api}
  s.authors = ['Tim Goddard <tim@goddard.nz>']
  s.version = "0.0.1"
  s.date = %q{2020-02-10}
  s.summary = %q{rack-oidc-api provides a JWT validation middleware which automatically discovers the settings supported by a given OIDC provider, and validates the token against the published keys.}
  s.files = [
    "lib/rack-oidc-api/middleware.rb"
  ]
  s.require_paths = ["lib"]
  s.license = "MIT"
  s.add_runtime_dependency 'rack'
  s.add_runtime_dependency 'jwt', '~> 2.2'
end
