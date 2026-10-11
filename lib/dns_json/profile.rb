# frozen_string_literal: true

module DNSJSON
  class Profile
    HEADER = (%w[ID Opcode RCODE] + BITS.keys + COUNTS).freeze
    GROUPS = %i[header question answer authority additional rdata hex metadata extensions].freeze
    def initialize(include: GROUPS, required: [], prohibited: [], one_bit_as: :number, privacy: false)
      raise ArgumentError, "unknown profile group" unless (include - GROUPS).empty?
      raise ArgumentError, "one_bit_as must be :number or :boolean" unless %i[number boolean].include?(one_bit_as)

      @include = include.dup.freeze
      @required = required.map { |name| name.to_s.dup.freeze }.freeze
      @prohibited = prohibited.map { |name| name.to_s.dup.freeze }.freeze
      @one_bit_as = one_bit_as
      @privacy = privacy
      freeze
    end

    def validate(data)
      @required.reject { |k| data.key?(k) }.map { |k| ValidationError.new("profile requires member", pointer: "/#{k}") } +
        @prohibited.select { |k| data.key?(k) }.map { |k| ValidationError.new("profile prohibits member", pointer: "/#{k}") }
    end

    def apply(data)
      data.each_with_object({}) do |(key, value), output|
        next if @prohibited.include?(key) || (@privacy && %w[ID additionalRRs additionalOctetsHEX].include?(key))
        next unless selected?(key)

        nested = %w[queryMessage responseMessage compressedNAME compressedQNAME rrSet].include?(key) || SECTIONS.any? { |s| key == "#{s}RRs" }
        unless nested
          output[key] = DNSJSON.copy(value)
          if BITS.key?(key) || key == "isCompressed"
            bit = [true, 1].include?(value)
            output[key] = if @one_bit_as == :boolean
                            bit
                          else
                            (bit ? 1 : 0)
                          end
          end
          next
        end
        output[key] = case value
                      when Hash then apply(value)
                      when Array then value.map { |v| v.is_a?(Hash) ? apply(v) : v }
                      else value
                      end
      end
    end

    def selected?(key)
      return true if %w[queryMessage responseMessage].include?(key)
      return @include.include?(:hex) if key.end_with?("HEX")
      return @include.include?(:header) if HEADER.include?(key)
      return @include.include?(:question) if %w[QNAME QTYPE QTYPEname QCLASS QCLASSname compressedQNAME questionRRs].include?(key)
      return @include.include?(:answer) if key == "answerRRs"
      return @include.include?(:authority) if key == "authorityRRs"
      return @include.include?(:additional) if key == "additionalRRs"
      return @include.include?(:rdata) if RData::FORMATS.value?(key.delete_prefix("rdata")) && key.start_with?("rdata")
      return @include.include?(:metadata) if %w[dateString dateSeconds comment].include?(key)
      return true if %w[NAME TYPE TYPEname CLASS CLASSname TTL RDLENGTH rrSet compressedNAME isCompressed length].include?(key)

      @include.include?(:extensions)
    end
    FULL = new
    LOGGING = new(include: %i[header question answer authority additional rdata metadata])
    PRIVACY = new(include: %i[header question answer authority rdata], privacy: true)
  end
end
