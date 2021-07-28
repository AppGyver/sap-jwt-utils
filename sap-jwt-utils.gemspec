# frozen_string_literal: true

require_relative "lib/sap/jwt/version"

Gem::Specification.new do |spec|
  spec.name          = "sap-jwt-utils"
  spec.version       = Sap::Jwt::VERSION
  spec.authors       = ["Richard Anderson"]
  spec.email         = ["richard.anderson@appgyver.com"]

  spec.summary       = "SAP JWT Utils"
  spec.description   = "SAP JWT Utils"
  spec.homepage      = "https://github.com/appgyver/sap-jwt-utils"
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.4.0")

  spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/appgyver/sap-jwt-utils"
  spec.metadata["changelog_uri"] = "https://github.com/appgyver/sap-jwt-utils/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{\A(?:test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "jwt"
  spec.add_dependency "faraday"
  spec.add_dependency "multi_json"
end
