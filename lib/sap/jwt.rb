# frozen_string_literal: true

require_relative "jwt/version"

require "faraday"
require "jwt"
require "multi_json"

# OpenID Connect ID Token Validation
# https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
#
# SAP Token Validation
# https://github.wdf.sap.corp/pages/CPSecurity/Knowledge-Base/03_ApplicationSecurity/TokenValidation/
module Sap
  module Jwt
    class VerificationError < StandardError; end

    class FetchJwksError < VerificationError; end

    class FetchUserTokenError < VerificationError; end

    class FetchOpenIdConfigurationError < VerificationError; end

    class MissingAccessTokenError < VerificationError; end

    class AuthorizedPartyValidationFailure < VerificationError; end

    class AudienceValidationFailure < VerificationError; end

    def self.request_headers
      {
        "User-Agent" => "appgyver/sap-jwt"
      }
    end

    # Parse the JWT access token
    #
    # Response includes both
    # - "access token" (access_token.token), and
    # - "id token" (access_token.params['id_token']).
    #
    # Both have the same jti token identifier, but only "access token" provides the XSUAA roles
    # and user's real name.
    #
    # Behaviour is inherited from the underlying open source product. It will always
    # additionally issue an OIDC token, but there is currently no supported scenario on BTP
    # with XSUAA OIDC tokens.
    #
    # Hence, the only "access token" is used and "id token" is not read.
    #
    # Example JWT payload:
    #   {"jti"=>"a62729d4d76f4e1c8054919cdfa34630",
    #   "ext_attr"=>
    #     {"enhancer"=>"XSUAA",
    #     "subaccountid"=>"06c0ad74-d224-463c-b46e-5f4d9c4bbcab",
    #     "zdn"=>"appgyver-int"},
    #   "xs.system.attributes"=>
    #     {"xs.rolecollections"=>
    #       ["Destination Administrator",
    #       "Cloud Connector Administrator",
    #       "Subaccount Administrator",
    #       "Connectivity and Destination Administrator"]},
    #   "given_name"=>"Richard",
    #   "family_name"=>"Anderson",
    #   "xs.user.attributes"=>{},
    #   "sub"=>"659444b2-372f-469d-ad9f-493827f759ab",
    #   "user_id"=>"659444b2-372f-469d-ad9f-493827f759ab",
    #   "scope"=>["openid"],
    #   "client_id"=>"sap-auth-playground!t30010",
    #   "cid"=>"sap-auth-playground!t30010",
    #   "azp"=>"sap-auth-playground!t30010",
    #   "grant_type"=>"authorization_code",
    #   "origin"=>"sap.default",
    #   "user_name"=>"richard.anderson@sap.com",
    #   "email"=>"richard.anderson@sap.com",
    #   "auth_time"=>1624011573,
    #   "rev_sig"=>"39022418",
    #   "iat"=>1624012747,
    #   "exp"=>1624617547,
    #   "iss"=> "https://appgyver-int.authentication.sap.hana.ondemand.com/oauth/token",
    #   "zid"=>"20f2417e-38ef-4007-9d66-d990b9c994ab",
    #   "aud"=>["openid", "sap-auth-playground!t30010"]}
    def self.verify!(token, iss:, aud:, jwks:, client_id: nil, verify_iss: true, verify_aud: true, verify_iat: true, algorithms: ["RS256"])
      options = {
        verify_iss: verify_iss,
        verify_iat: verify_iat,
        verify_aud: verify_aud,
        aud: aud,
        algorithms: algorithms,
        jwks: jwks,
        iss: iss
      }

      payload, header = ::JWT.decode(token, nil, true, options)

      validate_azp!(payload, authorized_party: client_id) if validate_azp?(payload, client_id)
      validate_aud!(payload, aud)

      [payload, header]
    rescue JWT::DecodeError => e
      raise VerificationError, e
    end

    def self.verify_with_headers!(token, aud:, uaadomain:, algorithms: ["RS256"])
      jwks_uri = nil

      options = {
        verify_iat: true,
        verify_aud: false, # Use validate_aud!() for service broker clone audiences
        aud: aud,
        algorithms: algorithms,
        jwks: ->(_opts) { fetch_jwks(jwks_uri) },
        verify_iss: false, # trusted value of issuer is not available with header verification
        iss: nil
      }

      payload, header = ::JWT.decode(token, nil, true, options) do |headers, payload|
        jwks_uri = parse_jku!(headers, payload, uaadomain)

        true
      end

      unless validate_aud!(payload, aud)
        raise(
          AudienceValidationFailure,
          "Expected audience '#{aud}' to match exactly or with '|b' suffix to '#{payload["aud"]}'"
        )
      end

      [payload, header]
    rescue JWT::DecodeError => e
      raise VerificationError, e
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
    # https://github.wdf.sap.corp/pages/CPSecurity/Knowledge-Base/03_ApplicationSecurity/TokenValidation/#get-token-keys-url-jwks-url
    def self.fetch_jwks(url)
      raise FetchJwksError, "Missing JWK URL: Could not fetch JWKs" unless url

      response = Faraday.get(url, request_headers)

      raise FetchJwksError, "Failed to fetch #{url}" unless response.success?

      MultiJson.load(response.body, symbolize_keys: true)
    end

    # Authentication endpoint info (tenant specific)
    #
    # https://TENANT.authentication.sap.hana.ondemand.com/.well-known/openid-configuration
    def self.fetch_openid_configuration(url)
      raise FetchOpenIdConfigurationError, "Missing OpenID Configuration metadata URL" unless url

      response = Faraday.get(url, request_headers)

      raise FetchOpenIdConfigurationError, "Failed to fetch #{url}" unless response.success?

      MultiJson.load(response.body, symbolize_keys: true)
    end

    # Fetch JWT User Token which using the UAA specific "urn:ietf:params:oauth:grant-type:jwt-bearer"
    # flow. The User Token contains detailed role names in its "scopes" claim.
    #
    # SAP documentation:
    # https://help.sap.com/viewer/cca91383641e40ffbe03bdc78f00f681/Cloud/en-US/39f538ad62e144c58c056ebc34bb6890.html
    def self.fetch_jwt_bearer_token(url, client_id:, client_secret:, assertion:)
      response = Faraday.post(url) do |req|
        req.headers = {
          "Content-Type" => "application/x-www-form-urlencoded"
        }
        req.body = URI.encode_www_form(
          {
            client_id: client_id,
            client_secret: client_secret,
            grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
            token_format: "jwt",
            response_type: "token",
            assertion: assertion
          }
        )
      end

      raise FetchUserTokenError, "Failed to fetch jwt-bearer token: #{response.body}" unless response.success?

      MultiJson.load(response.body, symbolize_keys: true)
    end

    # Parse JWK uri from JWT headers.
    # Raise error
    # - if hostname for JWK source (jku) does not match hostname of the token's issuer (iss)
    # - if JWK source (jku) hostname is outside of trusted uaadomain (originally provided by XSUAA)
    #
    # Returns JWK source url as string, for example
    # => "https://sub-dev-btp-gyver.authentication.sap.hana.ondemand.com/token_keys"
    private_class_method def self.parse_jku!(headers, payload, uaadomain)
      jku = URI.parse(headers["jku"])
      iss = URI.parse(payload["iss"])

      unless jku.hostname.end_with?(uaadomain)
        raise VerificationError, "JWK source '#{jku}' does not match tenant's uaadomain '#{uaadomain}'"
      end

      unless jku.hostname == iss.hostname
        raise VerificationError, <<-ERROR.squish
          JWK issuer hostname '#{iss.hostname}'
          does not match JWK source hostname '#{jwk.hostname}'
        ERROR
      end

      jku.to_s
    rescue URI::InvalidURIError => e
      raise VerificationError, "Invalid URI from JWT: #{e}"
    end

    # Validate Authorized Party
    # https://github.wdf.sap.corp/pages/CPSecurity/Knowledge-Base/03_ApplicationSecurity/TokenValidation/
    #
    # Validation failures:
    # - aud claim AND azp claim are undefined / empty
    # - azp does not match trusted client_id (or xs application id)
    # - OR aud does not contain trusted client_id (or xs application id) provided as part of VCAP_SERVICES.
    #
    # The "aud" attribute is validated by providing "aud" in jwt_options with verify_aud:true
    #
    # NOTE ABOUT "aud" and "azp":
    #
    # The "aud" claim in the ID Token contains our client_id and additionally a list of other client_ids.
    # In case of multiple audiences, SAP ID Tokens do not contain our client id (via VCAP_SERVICES)
    # in the "azp" field. Intead "azp" contains the client_id of the remote service (instead of ours),
    # although that client_id is also present in the "aud" field.
    #
    # OpenID Token Validation spec considers this case of "azp" validation with SHOULD:
    #   https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
    #   4. If the ID Token contains multiple audiences,
    #      the Client SHOULD verify that an azp Claim is present.
    #   5. If an azp (authorized party) Claim is present,
    #      the Client SHOULD verify that its client_id is the Claim Value.
    #
    # Because point (5) will not be true with SAP ID Tokens, we may skip "azp" validation if
    # client_id is not ours and "aud" has multiple client_ids.
    private_class_method def self.validate_azp!(payload, authorized_party:)
      azp = payload["azp"]

      return if azp && azp == authorized_party

      raise AuthorizedPartyValidationFailure, "Expected '#{authorized_party}', received: '#{azp}'"
    end

    # Valdiate SAP/XSUAA specifics of the Audience.
    #
    # The exact match of "aud" is already validated by JWT.decode.
    #
    # However, in case the scope contains a namespace then the audience contains the namespace as well.
    # For example, this scope xsapp!b4711.namespace.ns.write results in an audience
    # "xsapp!b4711.namespace.ns". That means the audience validator has to trim the namespace(s)
    # before it compares it with the xs application id.
    #
    # Because the client id is added to the list of audiences, you may find client ids of following
    # service instance tokens in the aud similar to "sb-d447781d-c010-4c19-af30-ed49097f22de!b446|xsapp!b4711".
    # In this case the audience matches in case it ends with "|xsapp!b4711".
    private_class_method def self.validate_aud!(payload, aud)
      payload["aud"].each do |a|
        return true if a == aud
        return true if a.end_with?(aud)
      end

      false
    end

    # See comments and reasoning at .validate_azp!
    private_class_method def self.validate_azp?(payload, client_id)
      client_id && payload["client_id"] == client_id
    end
  end
end
