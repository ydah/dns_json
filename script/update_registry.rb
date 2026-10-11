# frozen_string_literal: true

require "csv"
require "yaml"
require_relative "prepare_fixtures"
rows = CSV.read(ReferenceFixtures.fetch("rr_types.csv"), headers: true)
registry = rows.filter_map do |row|
  [row["Value"].to_i, row["TYPE"]] if row["Value"].match?(/\A\d+\z/) && row["TYPE"].match?(/\A[A-Z][A-Z0-9-]*\z/)
end.to_h
path = File.join(ReferenceFixtures::ROOT, "data/rr_types.yml")
if ARGV.include?("--write")
  File.write(path, registry.to_yaml)
else
  raise "Registry mismatch; audit the pin then run --write" unless YAML.safe_load_file(path) == registry
end
puts "Verified #{registry.length} IANA RR type identifiers"
