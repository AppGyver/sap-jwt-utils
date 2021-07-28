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
