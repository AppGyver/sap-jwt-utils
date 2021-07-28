# frozen_string_literal: true

require_relative "jwt/version"

require "faraday"
require "multi_json"
module Sap
  module Jwt
    class FetchJwksError < StandardError; end

    class FetchOpenIdConfigurationError < StandardError; end

    class MissingAccessTokenError < StandardError; end

    def self.request_headers
      {
        "User-Agent" => "appgyver/sap-jwt"
      }
    end

    # Fetch one or multiple JWKs which are used for verifying the token signature.
    #
    # The JWK URL should be retrieved from the discovery endpoint.
    # The "same" JWK URL is also present in the JWT Token's Header section, but according to the
    # OIDC specification, "ID tokens SHOULD NOT use the `jku` or `jwk` header parameter fields."
    #
    # In multi tenancy scenarios, the JWKs must be downloaded from an SAP-owned domain
    # and not customer-controlled domains.
    #
    # https://github.wdf.sap.corp/pages/CPSecurity/Knowledge-Base/03_ApplicationSecurity/TokenValidation/
    def self.fetch_jwks(site)
      jwks_uri = fetch_openid_configuration(site)[:jwks_uri]

      response = Faraday.get(jwks_uri, request_headers)

      raise FetchJwksError, "Failed to fetch #{jwks_uri}" unless response.success?

      MultiJson.load(response.body, symbolize_names: true)
    end

    # Authentication endpoint info (tenant specific)
    #
    # https://TENANT.authentication.sap.hana.ondemand.com/.well-known/openid-configuration
    def self.fetch_openid_configuration(site, path = "/.well-known/openid-configuration")
      url = "#{site}#{path}"
      response = Faraday.get(url, request_headers)

      raise FetchOpenIdConfigurationError, "Failed to fetch #{url}" unless response.success?

      MultiJson.load(response.body, symbolize_names: true)
    end
  end
end
