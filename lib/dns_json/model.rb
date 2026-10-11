# frozen_string_literal: true

module DNSJSON
  class Message
    PROPERTIES = YAML.safe_load_file(File.expand_path("../../data/properties.yml", __dir__)).transform_values do |properties|
      properties.transform_values(&:freeze).freeze
    end.freeze
    PROPERTIES.each { |name, spec| define_method(spec.fetch("accessor")) { self[name] } }
    attr_reader :problems, :warnings

    def initialize(data = {}, strict: true, profile: nil, problems: [], **limits)
      raise ValidationError, "expected an object" unless data.is_a?(Hash)

      @limits = DNSJSON.validate_limits(limits)
      @strict = strict
      @data = DNSJSON.copy(data)
      @problems = problems.freeze
      @warnings = validate
      @warnings.concat(profile.validate(@data)) if profile
      raise @warnings.first if strict && !@warnings.empty?
    end

    def [](key) = @data[key.to_s]
    def to_h = DNSJSON.copy(@data)
    def malformed? = !@problems.empty?
    def to_wire = Wire::Writer.new(@data, **@limits).write

    def to_json(*_args, profile: Profile::FULL)
      raise validate.first unless validate.empty?

      output = profile.apply(@data)
      errors = self.class.new(output, strict: false, **@limits).warnings + profile.validate(output)
      raise errors.first unless errors.empty?

      text = JSONWriter.generate(output)
      raise LimitError, "JSON output exceeds max_json_bytes" if text.bytesize > @limits[:max_json_bytes]

      text
    end

    def validate
      errors = []
      validate_value(@data, "", 0, errors)
      errors
    end

    private

    def error(errors, pointer, message) = errors << ValidationError.new(message, pointer: pointer)

    def validate_value(value, pointer, depth, errors, known: true)
      raise LimitError, "object exceeds max_depth" if depth > @limits[:max_depth]

      case value
      when Hash
        value.each do |key, item|
          raise ValidationError, "object keys must be strings" unless key.is_a?(String)

          path = "#{pointer}/#{key.gsub("~", "~0").gsub("/", "~1")}"
          validate_member(key, item, path, errors) if known
          child_known = known && (%w[queryMessage responseMessage compressedNAME compressedQNAME rrSet].include?(key) || SECTIONS.any? { |s| key == "#{s}RRs" })
          validate_value(item, path, depth + 1, errors, known: child_known)
        end
      when Array
        raise LimitError, "array exceeds max_records" if value.length > @limits[:max_records]

        value.each_with_index { |v, i| validate_value(v, "#{pointer}/#{i}", depth + 1, errors, known: known) }
      when Float
        error(errors, pointer, "number must be finite") unless value.finite?
      when String, Integer, TrueClass, FalseClass, NilClass
        nil
      else
        error(errors, pointer, "unsupported JSON value")
      end
    end

    def validate_member(key, value, path, errors)
      spec = PROPERTIES[key]
      range = spec && spec["minimum"] && (spec["minimum"]..spec["maximum"])
      error(errors, path, "integer out of range") if range && !(value.is_a?(Integer) && range.cover?(value))
      error(errors, path, "expected boolean or integer 0/1") if (BITS.key?(key) || key == "isCompressed") && ![0, 1, true, false].include?(value)
      if key.end_with?("HEX") && !(value.is_a?(String) && value.match?(/\A(?:[0-9A-F]{2})*\z/))
        error(errors, path, "expected uppercase even-length hexadecimal")
      end
      error(errors, path, "expected an array of objects") if (key.end_with?("RRs") || key == "rrSet") && !(value.is_a?(Array) && value.all?(Hash))
      error(errors, path, "expected an object") if %w[compressedNAME compressedQNAME queryMessage responseMessage].include?(key) && !value.is_a?(Hash)
      if (key.start_with?("rdata") || %w[NAME QNAME TYPEname CLASSname QTYPEname QCLASSname dateString comment].include?(key)) && !value.is_a?(String)
        error(errors, path, "expected a string")
      end
      error(errors, path, "expected finite nonnegative seconds") if key == "dateSeconds" && !(value.is_a?(Numeric) && value.finite? && value >= 0)
      return unless key == "dateString" && value.is_a?(String)

      begin
        match = /\A(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(?:Z|[+-]([01]\d|2[0-3]):([0-5]\d))\z/.match(value)
        raise ArgumentError unless match

        year, month, day, hour, minute, second = match.captures.first(6).map(&:to_i)
        raise ArgumentError unless Date.valid_date?(year, month, day, Date::GREGORIAN) && hour < 24 && minute < 60 && second <= 60

        Time.iso8601(value)
      rescue ArgumentError
        error(errors, path, "expected RFC 3339 timestamp")
      end
    end
  end

  class RR < Message; end

  class Pair < Message
    def initialize(data = {}, query: nil, response: nil, **)
      data = data.merge("queryMessage" => query.to_h) if query
      data = data.merge("responseMessage" => response.to_h) if response
      super(data, **)
    end

    def query = self["queryMessage"] && Message.new(self["queryMessage"], strict: @strict, **@limits)
    def response = self["responseMessage"] && Message.new(self["responseMessage"], strict: @strict, **@limits)
    def to_wire = raise(ConversionError, "select the query or response before writing wire data")
  end

  module JSONWriter
    def self.generate(value, key = nil)
      case value
      when Hash then "{#{value.map { |k, v| "#{JSON.generate(k, ascii_only: true)}:#{generate(v, k)}" }.join(",")}}"
      when Array then "[#{value.map { |v| generate(v) }.join(",")}]"
      when Float
        # dateSeconds forbids exponent notation; 17 significant digits retain binary64 precision.
        number = format("%.17g", value)
        if key == "dateSeconds" && number.match?(/[eE]/)
          mantissa, exponent = number.split(/[eE]/)
          digits = mantissa.delete(".")
          point = (mantissa.index(".") || mantissa.length) + exponent.to_i
          number = if point <= 0 then "0.#{"0" * -point}#{digits}"
                   elsif point >= digits.length then digits + ("0" * (point - digits.length))
                   else "#{digits[0, point]}.#{digits[point..]}"
                   end
        end
        number += ".0" unless number.match?(/[.eE]/)
        number
      else JSON.generate(value, ascii_only: true)
      end
    end
  end
end
