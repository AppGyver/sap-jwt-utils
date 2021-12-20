# frozen_string_literal: true

RSpec.describe Sap::Jwt do
  let(:site) { "https://subdomain-something.example.com" }
  let(:path) { "/.well-known/test-openid-configuration" }
  let(:oidc_url) { [site, path].join }

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

  describe ".verify!" do
    let(:jwks_json) do
      MultiJson.load(jwks_str, symbolize_names: true)
    end

    context "when successful" do
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

      it "verifies jwt of server-to-server communication" do
        Timecop.freeze(issued_at) do
          p, h = described_class.verify!(token, iss: iss, client_id: client_id, aud: aud, jwks: jwks_json)

          expect(p).to eq payload
          expect(h).to eq header
        end
      end

      context "when JWT decode fails" do
        it "throws Sap::Jwt::VerificationError" do
          allow(::JWT).to receive(:decode).and_raise(JWT::DecodeError)

          expect do
            described_class.verify!("invalid token", iss: "iss", client_id: "client_id", aud: "aud", jwks: "jwks_json")
          end.to raise_error(Sap::Jwt::VerificationError)
        end
      end

      context "when JWT signature has expired" do
        it "throws Sap::Jwt::VerificationError" do
          allow(::JWT).to receive(:decode).and_raise(JWT::ExpiredSignature)

          expect do
            described_class.verify!("invalid token", iss: "iss", client_id: "client_id", aud: "aud", jwks: "jwks_json")
          end.to raise_error(Sap::Jwt::VerificationError)
        end
      end
    end
  end

  describe "verify_with_headers!" do
    context "when successful" do
      let(:token) do
        "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vc3ViLWRldi1idHAtZ3l2ZXIuYXV0aGVudGljYXRpb24uc2FwLmhhbmEub25kZW1hbmQuY29tL3Rva2VuX2tleXMiLCJraWQiOiJkZWZhdWx0LWp3dC1rZXktLTU3NDgxMzk3IiwidHlwIjoiSldUIn0.eyJqdGkiOiI5ZTk2MGMyNDI5MmM0ZDI2YjU3NTc1ZjFhN2YyNTcyYSIsImV4dF9hdHRyIjp7ImVuaGFuY2VyIjoiWFNVQUEiLCJzdWJhY2NvdW50aWQiOiJkMzk5MjBlYi0xZTZmLTQ3NzUtOGIzYS0wNDQwODBhMmUyZDYiLCJ6ZG4iOiJzdWItZGV2LWJ0cC1neXZlciIsInNlcnZpY2VpbnN0YW5jZWlkIjoiZmEyNmI4OWMtNWM2Yi00N2ZmLThmMDItN2UyMTVkYzljMmQ1In0sInhzLnN5c3RlbS5hdHRyaWJ1dGVzIjp7InhzLnJvbGVjb2xsZWN0aW9ucyI6WyJMQ05DIEFkbWluaXN0cmF0b3IiLCJTdWJhY2NvdW50IEFkbWluaXN0cmF0b3IiXX0sImdpdmVuX25hbWUiOiJQZXRydXMiLCJ4cy51c2VyLmF0dHJpYnV0ZXMiOnt9LCJmYW1pbHlfbmFtZSI6IlJlcG8iLCJzdWIiOiJkMTY2NzI1MC0zNjBiLTRmZDUtYTdmYi1hNjEzMDZmNDhmNDYiLCJzY29wZSI6WyJkZXYtYnRwLWd5dmVyIWIzNzM0NS5hZG1pbiIsIm9wZW5pZCJdLCJjbGllbnRfaWQiOiJzYi1mYTI2Yjg5Yy01YzZiLTQ3ZmYtOGYwMi03ZTIxNWRjOWMyZDUhYjM3MzQ1fGRldi1idHAtZ3l2ZXIhYjM3MzQ1IiwiY2lkIjoic2ItZmEyNmI4OWMtNWM2Yi00N2ZmLThmMDItN2UyMTVkYzljMmQ1IWIzNzM0NXxkZXYtYnRwLWd5dmVyIWIzNzM0NSIsImF6cCI6InNiLWZhMjZiODljLTVjNmItNDdmZi04ZjAyLTdlMjE1ZGM5YzJkNSFiMzczNDV8ZGV2LWJ0cC1neXZlciFiMzczNDUiLCJncmFudF90eXBlIjoidXJuOmlldGY6cGFyYW1zOm9hdXRoOmdyYW50LXR5cGU6and0LWJlYXJlciIsInVzZXJfaWQiOiJkMTY2NzI1MC0zNjBiLTRmZDUtYTdmYi1hNjEzMDZmNDhmNDYiLCJvcmlnaW4iOiJzYXAuZGVmYXVsdCIsInVzZXJfbmFtZSI6InBldHJ1cy5yZXBvQHNhcC5jb20iLCJlbWFpbCI6InBldHJ1cy5yZXBvQHNhcC5jb20iLCJyZXZfc2lnIjoiMzc1ZTczYWIiLCJpYXQiOjE2Mzk3NDEwMTAsImV4cCI6MTY0MDM0NTgxMCwiaXNzIjoiaHR0cHM6Ly9zdWItZGV2LWJ0cC1neXZlci5hdXRoZW50aWNhdGlvbi5zYXAuaGFuYS5vbmRlbWFuZC5jb20vb2F1dGgvdG9rZW4iLCJ6aWQiOiIwZTcxYjIxNC00YzBlLTQ3ZTAtOWNhMS03YzRhODkyZGNlYTkiLCJhdWQiOlsic2ItZmEyNmI4OWMtNWM2Yi00N2ZmLThmMDItN2UyMTVkYzljMmQ1IWIzNzM0NXxkZXYtYnRwLWd5dmVyIWIzNzM0NSIsImRldi1idHAtZ3l2ZXIhYjM3MzQ1Iiwib3BlbmlkIl19.Uip_-Kpi0Rxmjk02hq1qnNkt5dt3MSYajrgfs1yAZ5B58Aq8a_QQwBd8Esd2_HwhblOfMtcP-DpME7abnC38_VRGuh6SUMnG-UxVOvROmmS8O0kxaG1XFMR1EVK2bM5fFR5ov0K7RjNPBwufNkhzVWdwLbE6xp67Q-LtoUg8XxBemihg1l9vF3KZTiZk91VY39CFAYydp3cKkeVke0LQBOX7HnFAOuRpiUD9wQ_k1Fa6gCt4EeD7hnPaEI0NsUmRWCEtUsz9dQ7QVWQnGdKBfOxXYCwbStjLUY4CypYf0v4C-uPZgHtl1HdDI4YwCllfXR7xvumC96TFGTjHZRP5qQ"
      end

      let(:header) do
        {
          "typ" => "JWT",
          "alg" => "RS256",
          "jku" => "https://sub-dev-btp-gyver.authentication.sap.hana.ondemand.com/token_keys",
          "kid" => "default-jwt-key--57481397"
        }
      end

      let(:payload) do
        {
          "aud" => [
            "sb-fa26b89c-5c6b-47ff-8f02-7e215dc9c2d5!b37345|dev-btp-gyver!b37345",
            "dev-btp-gyver!b37345",
            "openid"
          ],
          "azp" => "sb-fa26b89c-5c6b-47ff-8f02-7e215dc9c2d5!b37345|dev-btp-gyver!b37345",
          "cid" => "sb-fa26b89c-5c6b-47ff-8f02-7e215dc9c2d5!b37345|dev-btp-gyver!b37345",
          "client_id" => "sb-fa26b89c-5c6b-47ff-8f02-7e215dc9c2d5!b37345|dev-btp-gyver!b37345",
          "email" => "petrus.repo@sap.com",
          "exp" => 1640345810,
          "ext_attr" => {
            "enhancer" => "XSUAA",
            "serviceinstanceid" => "fa26b89c-5c6b-47ff-8f02-7e215dc9c2d5",
            "subaccountid" => "d39920eb-1e6f-4775-8b3a-044080a2e2d6",
            "zdn" => "sub-dev-btp-gyver"
          },
          "family_name" => "Repo",
          "given_name" => "Petrus",
          "grant_type" => "urn:ietf:params:oauth:grant-type:jwt-bearer",
          "iat" => 1639741010,
          "iss" => "https://sub-dev-btp-gyver.authentication.sap.hana.ondemand.com/oauth/token",
          "jti" => "9e960c24292c4d26b57575f1a7f2572a",
          "origin" => "sap.default",
          "rev_sig" => "375e73ab",
          "scope" => [
            "dev-btp-gyver!b37345.admin",
            "openid"
          ],
          "sub" => "d1667250-360b-4fd5-a7fb-a61306f48f46",
          "user_id" => "d1667250-360b-4fd5-a7fb-a61306f48f46",
          "user_name" => "petrus.repo@sap.com",
          "xs.system.attributes" => {
            "xs.rolecollections" => [
              "LCNC Administrator",
              "Subaccount Administrator"
            ]
          },
          "xs.user.attributes" => {},
          "zid" => "0e71b214-4c0e-47e0-9ca1-7c4a892dcea9"
        }
      end

      let(:issued_at) { 1639741010 }
      let(:now) { Time.at(issued_at) }
      let(:aud) { "dev-btp-gyver!b37345" }
      let(:uaadomain) { "authentication.sap.hana.ondemand.com" }

      it "verifies jwt with jwks fetched from the header" do
        VCR.use_cassette("jwt_token_keys/dev-btp-gyver") do
          Timecop.freeze(now) do
            p, h = described_class.verify_with_headers!(token, aud: aud, uaadomain: uaadomain)

            expect(p).to eq payload
            expect(h).to eq header
          end
        end
      end

      context "when JWT decode fails" do
        it "throws Sap::Jwt::VerificationError" do
          allow(::JWT).to receive(:decode).and_raise(JWT::DecodeError)

          expect do
            described_class.verify_with_headers!(token, aud: aud, uaadomain: uaadomain)
          end.to raise_error(Sap::Jwt::VerificationError)
        end
      end

      context "when JWT signature has expired" do
        before do
          allow(::JWT).to receive(:decode).and_raise(JWT::ExpiredSignature)
        end

        it "throws Sap::Jwt::VerificationError" do
          expect do
            described_class.verify_with_headers!(token, aud: aud, uaadomain: uaadomain)
          end.to raise_error(Sap::Jwt::VerificationError)

          expect(::JWT).to have_received(:decode)
        end
      end
    end
  end

  describe ".fetch_jwks" do
    let(:jwks_url) { "https://sap-provisioning.authentication.sap.example.com/token_keys" }
    let(:response) { instance_double(Faraday::Response) }
    let(:body_string) { '{"it": "works, jwk here"}' }
    let(:body_parsed) { { it: "works, jwk here" } }

    before do
      allow(Faraday)
        .to receive(:get)
        .with(jwks_url, default_headers)
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
        expect(described_class.fetch_jwks(jwks_url))
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
          described_class.fetch_jwks(jwks_url)
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
        .with(oidc_url, default_headers)
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
        expect(described_class.fetch_openid_configuration(oidc_url))
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
          described_class.fetch_openid_configuration(oidc_url)
        end.to raise_error Sap::Jwt::FetchOpenIdConfigurationError
      end
    end
  end
end
