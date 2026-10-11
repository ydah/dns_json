# frozen_string_literal: true

module DNSJSON
  module Registry
    TYPES = YAML.safe_load_file(File.expand_path("../../data/rr_types.yml", __dir__)).transform_values(&:freeze).freeze
    CLASSES = { 1 => "IN", 3 => "CH", 4 => "HS" }.freeze
    def self.type(number) = TYPES.fetch(number) { "TYPE#{number}" }
    def self.klass(number) = CLASSES.fetch(number) { "CLASS#{number}" }

    def self.number(text, kind = :type)
      table, prefix = kind == :type ? [TYPES, "TYPE"] : [CLASSES, "CLASS"]
      number = table.key(text) || (text.to_s.match?(/\A#{prefix}\d+\z/) && text.delete_prefix(prefix).to_i)
      raise ConversionError, "invalid #{kind} name" unless number.is_a?(Integer) && number.between?(0, 65_535)

      number
    end
  end
end
