# frozen_string_literal: true

require "json"
require "yaml"
require "time"
require "date"
require "ipaddr"

require_relative "dns_json/version"

module DNSJSON
  VERSION = DnsJson::VERSION
  MEDIA_TYPE = "application/dns+json"
  LIMITS = { max_bytes: 65_535, max_records: 4096, max_pointers: 128, max_json_bytes: 4_194_304, max_depth: 32 }.freeze
  BITS = { "QR" => 15, "AA" => 10, "TC" => 9, "RD" => 8, "RA" => 7, "AD" => 5, "CD" => 4 }.freeze
  SECTIONS = %w[question answer authority additional].freeze
  COUNTS = %w[QDCOUNT ANCOUNT NSCOUNT ARCOUNT].freeze
  class Error < StandardError; end
  class ParseError < Error; end
  class ConversionError < Error; end
  class LimitError < ParseError; end

  class ValidationError < Error
    attr_reader :pointer

    def initialize(message, pointer: "")
      @pointer = pointer
      super("#{pointer.empty? ? "/" : pointer}: #{message}")
    end
  end
  Problem = Data.define(:offset, :reason)
  class DecimalToken
    attr_reader :source

    def initialize(source)
      @source = source
    end
  end

  def self.validate_limits(options)
    raise ArgumentError, "unknown limit" unless (options.keys - LIMITS.keys).empty?

    limits = LIMITS.merge(options)
    limits.each do |name, value|
      minimum = name == :max_depth ? 1 : 0
      raise ArgumentError, "#{name} must be an Integer >= #{minimum}" unless value.is_a?(Integer) && value >= minimum
    end
    limits
  end

  def self.normalize_decimals(value, errors, pointer = "", member = nil, known: true)
    case value
    when Hash
      value.to_h do |key, item|
        child_known = known && (%w[queryMessage responseMessage compressedNAME compressedQNAME rrSet].include?(key) || SECTIONS.any? { |s| key == "#{s}RRs" })
        path = "#{pointer}/#{key.gsub("~", "~0").gsub("/", "~1")}"
        [key, normalize_decimals(item, errors, path, known ? key : nil, known: child_known)]
      end
    when Array
      value.each_with_index.map { |item, index| normalize_decimals(item, errors, "#{pointer}/#{index}", known: known) }
    when DecimalToken
      errors << ValidationError.new("dateSeconds forbids signs and exponents", pointer: pointer) if member == "dateSeconds" && value.source.match?(/[eE-]/)
      Float(value.source)
    else value
    end
  end

  def self.hex(bytes) = bytes.unpack1("H*").upcase

  def self.unhex(text)
    raise ConversionError, "expected uppercase even-length hexadecimal" unless text.is_a?(String) && text.match?(/\A(?:[0-9A-F]{2})*\z/)

    [text].pack("H*")
  end

  def self.copy(value, depth = 0)
    raise LimitError, "object copy exceeds safe depth" if depth > 128

    case value
    when Hash then value.to_h { |k, v| [k.dup, copy(v, depth + 1)] }
    when Array then value.map { |v| copy(v, depth + 1) }
    when String then value.dup
    else value
    end
  end

  def self.parse(source, strict: true, profile: nil, **limits)
    raise ParseError, "JSON source must be a String" unless source.is_a?(String)

    limits = validate_limits(limits)
    raise LimitError, "JSON exceeds max_json_bytes" if source.bytesize > limits[:max_json_bytes]
    raise ParseError, "JSON source must contain only ASCII characters" unless source.ascii_only?

    data = JSON.parse(source, allow_duplicate_key: false, decimal_class: DecimalToken, max_nesting: limits[:max_depth])
    lexical_errors = []
    data = normalize_decimals(data, lexical_errors)
    raise ParseError, "expected a JSON object" unless data.is_a?(Hash)

    type = data.key?("queryMessage") || data.key?("responseMessage") ? Pair : Message
    raise lexical_errors.first if strict && !lexical_errors.empty?

    result = type.new(data, strict: strict, profile: profile, **limits)
    result.warnings.concat(lexical_errors)
    result
  rescue JSON::ParserError, EncodingError => e
    raise ParseError, e.message
  end

  def self.from_wire(bytes, date: nil, **limits)
    limits = validate_limits(limits)
    Wire::Reader.new(bytes, **limits).read(date: date)
  end
end

require_relative "dns_json/registry"
require_relative "dns_json/wire/name"
require_relative "dns_json/rdata"
require_relative "dns_json/model"
require_relative "dns_json/profile"
require_relative "dns_json/wire/reader"
require_relative "dns_json/wire/writer"
require_relative "dns_json/stream"
