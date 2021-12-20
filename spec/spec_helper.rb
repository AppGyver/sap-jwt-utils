# frozen_string_literal: true

require "sap/jwt"
require "timecop"
require "webmock/rspec"
require "vcr"

RSpec.configure do |config|
  WebMock.disable_net_connect!

  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  Timecop.safe_mode = true
end

VCR.configure do |config|
  config.cassette_library_dir = "fixtures/vcr_cassettes"
  config.hook_into :webmock
end
