# frozen_string_literal: true

RSpec.describe Sap::Jwt::RedisStore do
  describe ".fetch" do
    let(:mock_redis) { MockRedis.new }

    let(:default_headers) do
      {
        "User-Agent" => "appgyver/sap-jwt"
      }
    end

    let(:oidc_url) { "https://oidc.example.local/.well-known/openid-configuration" }
    let(:kind) { "test-kind" }
    let(:redis_key_name) { "sapjwt:#{kind}:#{oidc_url}" }
    let(:expires_in) { 1800 }
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

    context "when success and not in cache" do
      subject(:payload) { described_class.fetch(redis: mock_redis, kind: kind, url: oidc_url) }

      before do
        allow(response)
          .to receive(:success?)
          .and_return true

        allow(mock_redis)
          .to receive(:get)
          .twice
          .with(redis_key_name)
          .and_return(nil, body_string)

        allow(mock_redis)
          .to receive(:setex)
          .with(redis_key_name, expires_in, body_string)
          .and_return "OK"
      end

      it "updates cache and returns cached content as json" do
        expect(payload).to eq(body_parsed)

        expect(mock_redis)
          .to have_received(:setex)
          .with(redis_key_name, expires_in, body_string)
      end
    end

    context "when success and is cached" do
      subject(:payload) { described_class.fetch(redis: mock_redis, kind: kind, url: oidc_url) }

      before do
        allow(response)
          .to receive(:success?)
          .and_return true

        allow(mock_redis)
          .to receive(:get)
          .twice
          .with(redis_key_name)
          .and_return(body_string)

        allow(mock_redis).to receive(:setex)
      end

      it "does not update cache and returns cached content as json" do
        expect(payload).to eq(body_parsed)

        expect(mock_redis).not_to have_received(:setex)
      end
    end

    context "with failing http request" do
      before do
        allow(mock_redis)
          .to receive(:get)
          .once
          .with(redis_key_name)
          .and_return(nil) # not in cache

        allow(response)
          .to receive(:success?)
          .and_return false
      end

      it "raises exception" do
        expect do
          described_class.fetch(redis: mock_redis, kind: kind, url: oidc_url)
        end.to raise_error Sap::Jwt::FetchError
      end
    end
  end
end
