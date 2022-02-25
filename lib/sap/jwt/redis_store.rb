module Sap
  module Jwt
    class RedisStore
      def self.fetch(redis:, kind:, url:)
        update(redis, kind, url) if get(redis, kind, url).nil?

        MultiJson.load(get(redis, kind, url), symbolize_keys: true)
      end

      private_class_method def self.update(redis, kind, url)
        raise FetchError, "Missing URL for '#{kind}'" unless url

        response = Faraday.get(url, Sap::Jwt.request_headers)

        raise Sap::Jwt::FetchError, "Failed to fetch '#{kind}' from '#{url}'" unless response.success?

        expires_in_seconds = 30 * 60

        redis.setex(
          key_name(kind, url),
          expires_in_seconds,
          response.body
        )
      end

      private_class_method def self.get(redis, kind, url)
        redis.get(key_name(kind, url))
      end

      private_class_method def self.key_name(kind, url)
        "sapjwt:#{kind}:#{url}"
      end
    end
  end
end
