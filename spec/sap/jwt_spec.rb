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

    context "with authorization_code grant type" do
      let(:jwks_str) do
        '{
          "keys": [{
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "default-jwt-key--1137935149",
            "alg": "RS256",
            "value": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4UCgAtdjWTjG6qHjcdob\nsjk06JsQ6BWd20Q3yutK5n3+e6FCQlpXyBEN0pMIpNjWBx6/85HW/k2vwauwqQCC\nB4I00HgFXKDjWrktv1eve5MNiWNI1+InXLIQ72gZUVcUi9IjhN/0e/hDcALCIeVN\nTbW4ZHDqj5wZ5beP/9EzZWYP/sHT1XkWu/8deiT8bq1SysKtYxpt1WG01zqEaSSE\nOmsZ1tp/gzsbfYTCj+xs10Qmax4TP9AhaAsGY714GAU5w+8Nk2yAfUr+AFn8bQXN\nK46RwVqI83ZL6N70SiQy02mcsw4VVUaAhB1NnrkCfL2Wrmohw9lQOfEtYBrnoxEM\nLwIDAQAB\n-----END PUBLIC KEY-----",
            "n": "AOFAoALXY1k4xuqh43HaG7I5NOibEOgVndtEN8rrSuZ9_nuhQkJaV8gRDdKTCKTY1gcev_OR1v5Nr8GrsKkAggeCNNB4BVyg41q5Lb9Xr3uTDYljSNfiJ1yyEO9oGVFXFIvSI4Tf9Hv4Q3ACwiHlTU21uGRw6o-cGeW3j__RM2VmD_7B09V5Frv_HXok_G6tUsrCrWMabdVhtNc6hGkkhDprGdbaf4M7G32Ewo_sbNdEJmseEz_QIWgLBmO9eBgFOcPvDZNsgH1K_gBZ_G0FzSuOkcFaiPN2S-je9EokMtNpnLMOFVVGgIQdTZ65Any9lq5qIcPZUDnxLWAa56MRDC8"
          }]
        }'
      end

      let(:token) do
        "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vYXBwZ3l2ZXItaW50LmF1dGhlbnRpY2F0aW9uLnNhcC5oYW5hLm9uZGVtYW5kLmNvbS90b2tlbl9rZXlzIiwia2lkIjoiZGVmYXVsdC1qd3Qta2V5LS0xMTM3OTM1MTQ5IiwidHlwIjoiSldUIn0.eyJqdGkiOiI4OGNiNWY5NWQ5OWU0OTYxOWEyYWM1NzVmYWUyOTU0MCIsImV4dF9hdHRyIjp7ImVuaGFuY2VyIjoiWFNVQUEiLCJzdWJhY2NvdW50aWQiOiIwNmMwYWQ3NC1kMjI0LTQ2M2MtYjQ2ZS01ZjRkOWM0YmJjMTUiLCJ6ZG4iOiJhcHBneXZlci1pbnQifSwieHMuc3lzdGVtLmF0dHJpYnV0ZXMiOnsieHMucm9sZWNvbGxlY3Rpb25zIjpbIkRlc3RpbmF0aW9uIEFkbWluaXN0cmF0b3IiLCJDbG91ZCBDb25uZWN0b3IgQWRtaW5pc3RyYXRvciIsIlN1YmFjY291bnQgQWRtaW5pc3RyYXRvciIsIkNvbm5lY3Rpdml0eSBhbmQgRGVzdGluYXRpb24gQWRtaW5pc3RyYXRvciJdfSwiZ2l2ZW5fbmFtZSI6IlBldHJ1cyIsInhzLnVzZXIuYXR0cmlidXRlcyI6e30sImZhbWlseV9uYW1lIjoiUmVwbyIsInN1YiI6IjY1OTQ0NGIyLTM3MmYtNDY5ZC1hZDlmLTQ5MzgyN2Y3NTlhNCIsInNjb3BlIjpbIm9wZW5pZCJdLCJjbGllbnRfaWQiOiJzYi14c3VhYS1mb3ItZGV2ZWxvcG1lbnQhdDMwMDEwIiwiY2lkIjoic2IteHN1YWEtZm9yLWRldmVsb3BtZW50IXQzMDAxMCIsImF6cCI6InNiLXhzdWFhLWZvci1kZXZlbG9wbWVudCF0MzAwMTAiLCJncmFudF90eXBlIjoiYXV0aG9yaXphdGlvbl9jb2RlIiwidXNlcl9pZCI6IjY1OTQ0NGIyLTM3MmYtNDY5ZC1hZDlmLTQ5MzgyN2Y3NTlhNCIsIm9yaWdpbiI6InNhcC5kZWZhdWx0IiwidXNlcl9uYW1lIjoicGV0cnVzLnJlcG9Ac2FwLmNvbSIsImVtYWlsIjoicGV0cnVzLnJlcG9Ac2FwLmNvbSIsImF1dGhfdGltZSI6MTYyNzY2MzQ2NSwicmV2X3NpZyI6ImIyMzg0MDYwIiwiaWF0IjoxNjI3NjYzNzgxLCJleHAiOjE2MjgyNjg1ODEsImlzcyI6Imh0dHBzOi8vYXBwZ3l2ZXItaW50LmF1dGhlbnRpY2F0aW9uLnNhcC5oYW5hLm9uZGVtYW5kLmNvbS9vYXV0aC90b2tlbiIsInppZCI6IjIwZjI0MTdlLTM4ZWYtNDAwNy05ZDY2LWQ5OTBiOWM5OTRiNCIsImF1ZCI6WyJvcGVuaWQiLCJzYi14c3VhYS1mb3ItZGV2ZWxvcG1lbnQhdDMwMDEwIl19.TZJqXOEnZkKtm4VMESDmNWq-o7o-Uak7UI7i-h7FSoRjDshauk6wseEHK0B2-_olRHeKfvw13yGnUAIxCtK-mlyOasxYtUGxVG5f_uj1z2oxYas9PwxbD8nlKKc4TkVeSMWiO60NRHZzmXC63zIcjMilJvcpDeM9TJdaxS8BDiS5Xrspzw_h16mP468cwRoWOu3bGjs_FL3HM2DT-O721RgitfNeLrYpFH9p-wadbL8XYU9wH5q7HYUqk2NU9JQfXVncv0WFqff3NiGGU8FYh3gQb1OFmaSjasbRngIpeUcNUOXvsugct6qSZZjjWbRGY1qLfOwdEuAbiJAYUr38XQ"
      end

      let(:header) do
        {
          "typ" => "JWT",
          "alg" => "RS256",
          "jku" => "https://appgyver-int.authentication.sap.hana.ondemand.com/token_keys",
          "kid" => "default-jwt-key--1137935149"
        }
      end

      let(:payload) do
        {
          "aud" => [
            "openid",
            "sb-xsuaa-for-development!t30010"
          ],
          "auth_time" => 1627663465,
          "azp" => "sb-xsuaa-for-development!t30010",
          "cid" => "sb-xsuaa-for-development!t30010",
          "client_id" => "sb-xsuaa-for-development!t30010",
          "email" => "petrus.repo@sap.com",
          "exp" => 1628268581,
          "ext_attr" => {
            "enhancer" => "XSUAA",
            "subaccountid" => "06c0ad74-d224-463c-b46e-5f4d9c4bbc15",
            "zdn" => "appgyver-int"
          },
          "family_name" => "Repo",
          "given_name" => "Petrus",
          "grant_type" => "authorization_code",
          "iat" => 1627663781,
          "iss" => "https://appgyver-int.authentication.sap.hana.ondemand.com/oauth/token",
          "jti" => "88cb5f95d99e49619a2ac575fae29540",
          "origin" => "sap.default",
          "rev_sig" => "b2384060",
          "scope" => [
            "openid"
          ],
          "sub" => "659444b2-372f-469d-ad9f-493827f759a4",
          "user_id" => "659444b2-372f-469d-ad9f-493827f759a4",
          "user_name" => "petrus.repo@sap.com",
          "xs.system.attributes" => {
            "xs.rolecollections" => [
              "Destination Administrator",
              "Cloud Connector Administrator",
              "Subaccount Administrator",
              "Connectivity and Destination Administrator"
            ]
          },
          "xs.user.attributes" => {},
          "zid" => "20f2417e-38ef-4007-9d66-d990b9c994b4"
        }
      end

      # 2021-07-30 19:49:42
      let(:issued_at) { Time.local(2021, 7, 30, 19, 49, 42) }
      let(:iss) { "https://appgyver-int.authentication.sap.hana.ondemand.com/oauth/token" }
      let(:client_id) { "sb-xsuaa-for-development!t30010" }
      let(:aud) { client_id }

      it "parses jwt of user authentication" do
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
