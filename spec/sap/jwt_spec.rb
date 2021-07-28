# frozen_string_literal: true

RSpec.describe Sap::Jwt do
  it "has a version number" do
    expect(Sap::Jwt::VERSION).not_to be nil
  end
  let(:default_headers) do
    {
      "User-Agent" => "appgyver/sap-jwt"
    }
  end


  it "decodes token with options"

  it "validates audience 'aud'"

  it "validates audience 'azp'"

  it "fetches jwks"

  it "fetches jwt uri"

  describe ".request_headers" do
    it "defines request headers" do
      expect(described_class.request_headers)
        .to eq(default_headers)
    end
  end

  describe ".fetch_openid_configuration" do
    let(:site) { "https://subdomain-something.example.com" }
    let(:path) { "/.well-known/test-openid-configuration" }

    let(:url) { [site, path].join }

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

  it 'has default jwt options'

end
