# frozen_string_literal: true

RSpec.describe Sap::Jwt do
  let(:site) { "https://subdomain-something.example.com" }
  let(:path) { "/.well-known/test-openid-configuration" }
  let(:url) { [site, path].join }

  let(:default_headers) do
    {
      "User-Agent" => "appgyver/sap-jwt"
    }
  end

  it "has a version number" do
    expect(Sap::Jwt::VERSION).not_to be nil
  end

  describe ".request_headers" do
    it "defines request headers" do
      expect(described_class.request_headers)
        .to eq(default_headers)
    end
  end

  describe ".parse" do
    let(:jwks_json) do
      MultiJson.load(jwks_str, symbolize_names: true)
    end

    context "client_credentials grant type" do
      let(:jwks_str) do
        '{
            "keys": [{
                "kty": "RSA",
                "e": "AQAB",
                "use": "sig",
                "kid": "key-id-0",
                "alg": "RS256",
                "value": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/jN5v1mp/TVn9nTQoYV\nIUfCsUDHa3Upr5tDZC7mzlTrN2PnwruzyS7w1Jd+StqwW4/vn87ua2YlZzU8Ob0j\nR4lbOPCKaHIi0kyNtJXQvQ7LZPG8epQLbx0IIP/WLVVVtB8bL5OWuHma3pUnibbm\nATtbOh5LksQ2zLMngEjUF52JQyzTpjoQkahp0BNe/drlAqO253keiY63FL6belKj\nJGmSqdnotSXxB2ym+HQ0ShaNvTFLEvi2+ObkyjGWgFpQaoCcGq0KX0y0mPzOvdFs\nNT+rBFdkHiK+Jl638Sbim1z9fItFbH9hiVwY37R9rLtH1YKi3PuATMjf/DJ7mUlu\nDQIDAQAB\n-----END PUBLIC KEY-----",
                "n": "AMf4zeb9Zqf01Z_Z00KGFSFHwrFAx2t1Ka-bQ2Qu5s5U6zdj58K7s8ku8NSXfkrasFuP75_O7mtmJWc1PDm9I0eJWzjwimhyItJMjbSV0L0Oy2TxvHqUC28dCCD_1i1VVbQfGy-Tlrh5mt6VJ4m25gE7WzoeS5LENsyzJ4BI1BediUMs06Y6EJGoadATXv3a5QKjtud5HomOtxS-m3pSoyRpkqnZ6LUl8Qdspvh0NEoWjb0xSxL4tvjm5MoxloBaUGqAnBqtCl9MtJj8zr3RbDU_qwRXZB4iviZet_Em4ptc_XyLRWx_YYlcGN-0fay7R9WCotz7gEzI3_wye5lJbg0"
            }, {
                "kty": "RSA",
                "e": "AQAB",
                "use": "sig",
                "kid": "key-id-1",
                "alg": "RS256",
                "value": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/jN5v1mp/TVn9nTQoYV\nIUfCsUDHa3Upr5tDZC7mzlTrN2PnwruzyS7w1Jd+StqwW4/vn87ua2YlZzU8Ob0j\nR4lbOPCKaHIi0kyNtJXQvQ7LZPG8epQLbx0IIP/WLVVVtB8bL5OWuHma3pUnibbm\nATtbOh5LksQ2zLMngEjUF52JQyzTpjoQkahp0BNe/drlAqO253keiY63FL6belKj\nJGmSqdnotSXxB2ym+HQ0ShaNvTFLEvi2+ObkyjGWgFpQaoCcGq0KX0y0mPzOvdFs\nNT+rBFdkHiK+Jl638Sbim1z9fItFbH9hiVwY37R9rLtH1YKi3PuATMjf/DJ7mUlu\nDQIDAQAB\n-----END PUBLIC KEY-----",
                "n": "AMf4zeb9Zqf01Z_Z00KGFSFHwrFAx2t1Ka-bQ2Qu5s5U6zdj58K7s8ku8NSXfkrasFuP75_O7mtmJWc1PDm9I0eJWzjwimhyItJMjbSV0L0Oy2TxvHqUC28dCCD_1i1VVbQfGy-Tlrh5mt6VJ4m25gE7WzoeS5LENsyzJ4BI1BediUMs06Y6EJGoadATXv3a5QKjtud5HomOtxS-m3pSoyRpkqnZ6LUl8Qdspvh0NEoWjb0xSxL4tvjm5MoxloBaUGqAnBqtCl9MtJj8zr3RbDU_qwRXZB4iviZet_Em4ptc_XyLRWx_YYlcGN-0fay7R9WCotz7gEzI3_wye5lJbg0"
            }]
        }'
      end

      let(:token) do
        "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vc2FwLXByb3Zpc2lvbmluZy5hdXRoZW50aWNhdGlvbi5zYXAuaGFuYS5vbmRlbWFuZC5jb20vdG9rZW5fa2V5cyIsImtpZCI6ImtleS1pZC0xIiwidHlwIjoiSldUIn0.eyJqdGkiOiIxZmM5MmRmYjc1YjQ0M2MxOGQzZWU3OGFlOTAyMWZhNyIsImV4dF9hdHRyIjp7ImVuaGFuY2VyIjoiWFNVQUEiLCJzdWJhY2NvdW50aWQiOiJzYXAtcHJvdmlzaW9uaW5nIiwiemRuIjoic2FwLXByb3Zpc2lvbmluZyJ9LCJzdWIiOiJzYi10ZW5hbnQtb25ib2FyZGluZyF0MTMiLCJzY29wZSI6WyJzYXAtYXV0aC1wbGF5Z3JvdW5kIXQzMDAxMC5DYWxsYmFjayJdLCJjbGllbnRfaWQiOiJzYi10ZW5hbnQtb25ib2FyZGluZyF0MTMiLCJjaWQiOiJzYi10ZW5hbnQtb25ib2FyZGluZyF0MTMiLCJhenAiOiJzYi10ZW5hbnQtb25ib2FyZGluZyF0MTMiLCJncmFudF90eXBlIjoiY2xpZW50X2NyZWRlbnRpYWxzIiwicmV2X3NpZyI6Ijc3MWQ1MDFmIiwiaWF0IjoxNjI3NjQ3Mjk4LCJleHAiOjE2Mjc2OTA0OTgsImlzcyI6Imh0dHA6Ly9zYXAtcHJvdmlzaW9uaW5nLmxvY2FsaG9zdDo4MDgwL3VhYS9vYXV0aC90b2tlbiIsInppZCI6InNhcC1wcm92aXNpb25pbmciLCJhdWQiOlsic2FwLWF1dGgtcGxheWdyb3VuZCF0MzAwMTAiLCJzYi10ZW5hbnQtb25ib2FyZGluZyF0MTMiXX0.AUL15PbgdLP-sEilF1cbMgn1qbT1__7Ons_LFApWGwCo81uzPDv8ARqXPG6oZaxM_yMSQpKBBp2hTlHE0ge4_P7VDOpmFdgH1L2Wr5jGlzFfDbw7euws1cwr_aV111Ul4EZhQi5kFOXXMxeN3vFN3eCs8jr4ibTYPzlE1s8iNnWRDKnF_ALsR9D9JRoI3eKDNAWaD6QyH2z71XcMKDDgsQTmqfuhOHNGcCs-5s19RvAny0jHHGuIkfhfmlmtcg6PmxaH05mMoDm6sxQNLAXsvojdAVevGJmtabqdQufCpIVda6q5tR2WmNdLbtFtqLEgT2PAPAp2BHqtCGsGLZio5A"
      end

      let(:header) do
        {
          "typ" => "JWT",
          "alg" => "RS256",
          "jku" => "https://sap-provisioning.authentication.sap.hana.ondemand.com/token_keys",
          "kid" => "key-id-1"
        }
      end

      let(:payload) do
        {
          "aud" => [
            "sap-auth-playground!t30010",
            "sb-tenant-onboarding!t13"
          ],
          "azp" => "sb-tenant-onboarding!t13",
          "cid" => "sb-tenant-onboarding!t13",
          "client_id" => "sb-tenant-onboarding!t13",
          "exp" => 1627690498,
          "ext_attr" => {
            "enhancer" => "XSUAA",
            "subaccountid" => "sap-provisioning",
            "zdn" => "sap-provisioning"
          },
          "grant_type" => "client_credentials",
          "iat" => 1627647298,
          "iss" => "http://sap-provisioning.localhost:8080/uaa/oauth/token",
          "jti" => "1fc92dfb75b443c18d3ee78ae9021fa7",
          "rev_sig" => "771d501f",
          "scope" => [
            "sap-auth-playground!t30010.Callback"
          ],
          "sub" => "sb-tenant-onboarding!t13",
          "zid" => "sap-provisioning"
        }
      end

      let(:client_id) { "sap-auth-playground!t30010" }
      let(:aud) { client_id }
      let(:iss) { "http://sap-provisioning.localhost:8080/uaa/oauth/token" }

      # 2021-07-30T15:15:00
      let(:issued_at) { Time.local(2021, 7, 30, 15, 15, 0) }

      it "parses jwt of server-to-server communication" do
        Timecop.freeze(issued_at) do
          p, h = described_class.parse!(token, iss: iss, client_id: client_id, aud: aud, jwks: jwks_json)

          expect(p).to eq payload
          expect(h).to eq header
        end
      end
    end
  end

  describe ".fetch_jwks" do
    let(:jwks_uri) { "https://sap-provisioning.authentication.sap.example.com/token_keys" }
    let(:response) { instance_double(Faraday::Response) }
    let(:body_string) { '{"it": "works, jwk here"}' }
    let(:body_parsed) { { it: "works, jwk here" } }

    before do
      allow(Faraday)
        .to receive(:get)
        .with(jwks_uri, default_headers)
        .and_return response

      allow(response)
        .to receive(:body)
        .and_return body_string

      allow(described_class)
        .to receive(:fetch_openid_configuration)
        .and_return({ jwks_uri: jwks_uri })
    end

    context "when success" do
      before do
        allow(response)
          .to receive(:success?)
          .and_return true
      end

      it "returns json" do
        expect(described_class.fetch_jwks(site))
          .to eq(body_parsed)
      end
    end

    context "when failure" do
      before do
        allow(response)
          .to receive(:success?)
          .and_return false
      end

      it "raises FetchJwksError" do
        expect do
          described_class.fetch_jwks(site)
        end.to raise_error Sap::Jwt::FetchJwksError
      end
    end
  end

  describe ".fetch_openid_configuration" do
    let(:response) { instance_double(Faraday::Response) }
    let(:body_string) { '{"it": "works"}' }
    let(:body_parsed) { { it: "works" } }

    before do
      allow(Faraday)
        .to receive(:get)
        .with(url, default_headers)
        .and_return response

      allow(response)
        .to receive(:body)
        .and_return body_string
    end

    context "when success" do
      before do
        allow(response)
          .to receive(:success?)
          .and_return true
      end

      it "returns json" do
        expect(described_class.fetch_openid_configuration(site, path))
          .to eq(body_parsed)
      end
    end

    context "with failure" do
      before do
        allow(response)
          .to receive(:success?)
          .and_return false
      end

      it "raises FetchOpenIdConfigurationError" do
        expect do
          described_class.fetch_openid_configuration(site, path)
        end.to raise_error Sap::Jwt::FetchOpenIdConfigurationError
      end
    end
  end
end
