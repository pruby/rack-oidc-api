require 'json'
require 'thread'
require 'net/http'
require 'jwt'

module RackOidcApi
    BEARER_TOKEN_REGEX = %r{
        \ABearer\s{1}(      # starts with Bearer and a single space
        [a-zA-Z0-9\-\_]+\.  # 1 or more chars followed by a single period
        [a-zA-Z0-9\-\_]+\.  # 1 or more chars followed by a single period
        [a-zA-Z0-9\-\_]+    # 1 or more chars
        )\z                 # nothing trailing
    }ix

    ALGORITHMS = %w(RS256 RS384 RS512)

    class Middleware
        def initialize(app, opts)
            @app = app

            raise "provider must be specified" if !opts[:provider]
            raise "audience must be specified" if !opts[:audience]

            @provider = opts[:provider].gsub(/\/\z/, '')
            @audience = opts[:audience]
            @pinned_cert = opts[:pinned_provider_ssl]
            @lock = Mutex.new

            reload_options
        end

        def reload_options
            begin
                oidc_config_uri = URI("#{@provider}/.well-known/openid-configuration")
                oidc_config_raw = http_get(oidc_config_uri)
                raise "Failed to retrieve OIDC Discovery Data" unless oidc_config_raw
                oidc_config = JSON.parse(oidc_config_raw)
                raise "Invalid or missing OIDC Discovery Data" unless oidc_config

                jwks_uri = oidc_config['jwks_uri']
                raise "No JWKS URI in OIDC Discovery" unless jwks_uri

                # Do not allow JWKS from a different origin (scheme, host, port)
                jwks_uri = URI(jwks_uri)
                jwks_uri.scheme = oidc_config_uri.scheme
                jwks_uri.host = oidc_config_uri.host
                jwks_uri.port = oidc_config_uri.port

                jwks_raw = http_get(jwks_uri)
                raise "Failed to retrieve JWKS File" unless jwks_raw
                
                jwks = JSON.parse(jwks_raw)
                algorithms = ALGORITHMS - (ALGORITHMS - oidc_config['id_token_signing_alg_values_supported'] || [])

                keys = []
                jwks['keys'].each do |key|
                    rec = {}
                    key.each do |k, v|
                        rec[k.to_sym] = v
                    end
                    keys << rec
                end

                @jwks = {keys: keys}
                @algorithms = algorithms
                @valid = Time.now + 300
                @avail = true
            rescue JSON::JSONError
                @avail = false
                @valid = Time.now + 60
            rescue StandardError => e
                STDERR.puts(e.message)
                @avail = false
                @valid = Time.now + 60
            rescue URI::InvalidURIError => e
                STDERR.puts(e.message)
                @avail = false
                @valid = Time.now + 60
            end
        end

        def check_reload
            locked = @lock.try_lock
            return unless locked # Only have one reload checking thread at once
            begin
                if @valid < Time.now
                    reload_options
                end
            ensure
                @lock.unlock
            end
        end

        def call(env)
            header = env['HTTP_AUTHORIZATION']
            if !header
                return mkerror("Missing Authorization Header")
            end

            if !header.match(BEARER_TOKEN_REGEX)
                return mkerror("Invalid Bearer token")
            end

            _, token = header.split(/\s/, 2)

            check_reload
            if !@avail
                return mkerror("OIDC provider unavailable")
            end

            jwk_loader = proc do |options|
                @jwks
            end

            begin
                jwt = JWT.decode(token, nil, true, {
                    algorithms: @algorithms,
                    jwks: jwk_loader,
                    aud: @audience,
                    verify_aud: true,
                    nbf_leeway: 30,
                    exp_leeway: 30
                })
                env[:identity_token] = jwt
            rescue JWT::JWKError => e
                # Handle problems with the provided JWKs
                return mkerror("Invalid Bearer token")
            rescue JWT::DecodeError => e
                # Handle other decode related issues e.g. no kid in header, no matching public key found etc. 
                return mkerror(e.message)
            end

            @app.call(env)
        end

        private

        def mkerror(message)
            body    = { error: message }.to_json
            headers = { 'Content-Type' => 'application/json' }

            [401, headers, [body]]
        end

        def http_get(uri)
            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = uri.scheme != 'http'
            http.verify_mode = OpenSSL::SSL::VERIFY_PEER # Make sure we're verifying
            if @pinned_cert
                http.verify_callback = lambda do | preverify_ok, cert_store |
                    return false unless preverify_ok

                    # We only want to verify once, and fail the first time the callback
                    # is invoked (as opposed to checking only the last time it's called).
                    # Therefore we get at the whole authorization chain.
                    # The end certificate is at the beginning of the chain (the certificate
                    # for the host we are talking to)
                    end_cert = cert_store.chain[0]

                    # Only perform the checks if the current cert is the end certificate
                    # in the chain. We can compare using the DER representation
                    # (OpenSSL::X509::Certificate objects are not comparable, and for 
                    # a good reason). If we don't we are going to perform the verification
                    # many times - once per certificate in the chain of trust, which is wasteful
                    return true unless end_cert.to_der == cert_store.current_cert.to_der

                    public_key = end_cert.public_key.to_pem
                    @pinned_cert == public_key || @pinned_cert == OpenSSL::Digest::SHA256.hexdigest(public_key)
                end                  
            end
        end
    end
end
