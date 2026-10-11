# frozen_string_literal: true

module DNSJSON
  module RData
    FORMATS = YAML.safe_load_file(File.expand_path("../../data/rdata_formats.yml", __dir__)).transform_values { |v| v.fetch("name").freeze }.freeze
    NAMES = [2, 5, 12, 39].freeze
    BASE32 = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    class Cursor
      attr_reader :position

      def initialize(bytes, offset, length, max_pointers)
        @bytes = bytes
        @position = offset
        @ending = offset + length
        @max_pointers = max_pointers
      end

      def remaining = @ending - @position

      def take(size = remaining)
        raise ConversionError, "truncated RDATA" if size.negative? || @position + size > @ending || @position + size > @bytes.bytesize

        result = @bytes.byteslice(@position, size)
        @position += size
        result
      end

      def u8 = take(1).unpack1("C")
      def u16 = take(2).unpack1("n")
      def u32 = take(4).unpack1("N")

      def name
        labels, count = Wire::Name.read(@bytes, @position, max_pointers: @max_pointers)
        take(count)
        Wire::Name.display(labels)
      end

      def strings
        result = []
        result << take(u8) until remaining.zero?
        result
      end
    end

    def self.decode(type, bytes, offset, length, max_pointers: 128)
      return unless FORMATS.key?(type)

      c = Cursor.new(bytes, offset, length, max_pointers)
      result = case type
               when 1, 28
                 expected = type == 1 ? 4 : 16
                 raise ConversionError, "invalid address length" unless length == expected

                 IPAddr.new_ntoh(c.take).to_s
               when *NAMES then c.name
               when 16 then octets_text(c.strings.join)
               when 99 then c.strings.map { |s| quote(s) }.join(" ")
               when 15 then [c.u16, c.name].join(" ")
               when 33 then [c.u16, c.u16, c.u16, c.name].join(" ")
               when 25, 48, 60 then [c.u16, c.u8, c.u8, base64_encode(c.take)].join(" ")
               when 43, 59 then [c.u16, c.u8, c.u8, DNSJSON.hex(c.take)].join(" ")
               when 44 then [c.u8, c.u8, DNSJSON.hex(c.take)].join(" ")
               when 52, 53 then [c.u8, c.u8, c.u8, DNSJSON.hex(c.take)].join(" ")
               when 61 then base64_encode(c.take)
               when 62 then [c.u32, c.u16, *bitmap_decode(c.take)].join(" ")
               when 47 then [c.name, *bitmap_decode(c.take)].join(" ")
               when 50, 51
                 parts = [c.u8, c.u8, c.u16]
                 salt = DNSJSON.hex(c.take(c.u8))
                 parts << (salt.empty? ? "-" : salt)
                 parts.push(base32_encode(c.take(c.u8)), *bitmap_decode(c.take)) if type == 50
                 parts.join(" ")
               when 46
                 [Registry.type(c.u16), c.u8, c.u8, c.u32, timestamp(c.u32), timestamp(c.u32), c.u16, c.name,
                  base64_encode(c.take)].join(" ")
               when 45
                 precedence = c.u8
                 gateway_type = c.u8
                 algorithm = c.u8
                 gateway = case gateway_type
                           when 0 then "."
                           when 1 then IPAddr.new_ntoh(c.take(4)).to_s
                           when 2 then IPAddr.new_ntoh(c.take(16)).to_s
                           when 3 then c.name
                           else raise ConversionError, "unknown IPSECKEY gateway type"
                           end
                 key = c.take
                 [precedence, gateway_type, algorithm, gateway, key.empty? ? "." : base64_encode(key)].join(" ")
               when 55
                 hit_length = c.u8
                 algorithm = c.u8
                 key_length = c.u16
                 parts = [algorithm, DNSJSON.hex(c.take(hit_length)), base64_encode(c.take(key_length))]
                 parts << c.name until c.remaining.zero?
                 parts.join(" ")
               end
      raise ConversionError, "excess RDATA" unless c.remaining.zero?

      result
    rescue ArgumentError, EncodingError => e
      raise ConversionError, e.message
    end

    def self.encode(type, text)
      raise ConversionError, "unsupported structured RDATA type" unless FORMATS.key?(type)
      raise ConversionError, "RDATA must be a string" unless text.is_a?(String)
      return address(text, type == 1 ? 4 : 16) if [1, 28].include?(type)
      return Wire::Name.encode(text) if NAMES.include?(type)
      return strings_encode([text_octets(text)]) if type == 16
      return strings_encode(parse_strings(text)) if type == 99

      parts = text.split(/\s+/)
      result = case type
               when 15 then integer(parts.shift, 16) + Wire::Name.encode(required(parts.shift))
               when 33 then numbers(parts, 16, 16, 16) + Wire::Name.encode(required(parts.shift))
               when 25, 48, 60 then numbers(parts, 16, 8, 8) + b64(parts)
               when 43, 59 then numbers(parts, 16, 8, 8) + hex_tail(parts)
               when 44 then numbers(parts, 8, 8) + hex_tail(parts)
               when 52, 53 then numbers(parts, 8, 8, 8) + hex_tail(parts)
               when 61 then b64(parts)
               when 62 then numbers(parts, 32, 16) + bitmap_encode(parts.shift(parts.length))
               when 47 then Wire::Name.encode(required(parts.shift)) + bitmap_encode(parts.shift(parts.length))
               when 50, 51
                 head = numbers(parts, 8, 8, 16)
                 salt_text = required(parts.shift)
                 salt = salt_text == "-" ? "".b : DNSJSON.unhex(salt_text.upcase)
                 head += counted(salt)
                 head += counted(base32_decode(required(parts.shift))) + bitmap_encode(parts.shift(parts.length)) if type == 50
                 head
               when 46
                 head = integer(Registry.number(required(parts.shift)), 16) + numbers(parts, 8, 8, 32)
                 head += integer(parse_time(parts.shift), 32) + integer(parse_time(parts.shift), 32) + numbers(parts, 16)
                 head + Wire::Name.encode(required(parts.shift)) + b64(parts)
               when 45
                 gateway_type = parts[1]&.to_i
                 head = numbers(parts, 8, 8, 8)
                 gateway = required(parts.shift)
                 head += case gateway_type
                         when 0
                           raise ConversionError, "gateway type 0 requires dot" unless gateway == "."

                           "".b
                         when 1 then address(gateway, 4)
                         when 2 then address(gateway, 16)
                         when 3 then Wire::Name.encode(gateway)
                         else raise ConversionError, "unknown IPSECKEY gateway type"
                         end
                 key = if parts == ["."]
                         (parts.clear
                          "".b)
                       else
                         b64(parts)
                       end
                 head + key
               when 55
                 algorithm = integer(parts.shift, 8)
                 hit = DNSJSON.unhex(required(parts.shift).upcase)
                 key = base64_decode(required(parts.shift))
                 integer(hit.bytesize, 8) + algorithm + integer(key.bytesize, 16) + hit + key + parts.shift(parts.length).map { |n|
                   Wire::Name.encode(n)
                 }.join.b
               end
      raise ConversionError, "excess RDATA fields" unless parts.empty?
      raise ConversionError, "RDATA exceeds 65535 bytes" if result.bytesize > 65_535

      result
    rescue ArgumentError, EncodingError => e
      raise ConversionError, e.message
    end

    def self.base64_encode(bytes) = [bytes].pack("m0")
    def self.base64_decode(text) = text.unpack1("m0")

    def self.required(value)
      raise ConversionError, "missing RDATA field" if value.nil?

      value
    end

    def self.integer(value, bits)
      raise ConversionError, "invalid unsigned integer" unless required(value).to_s.match?(/\A\d+\z/)

      value = value.to_i
      raise ConversionError, "integer out of range" unless value.between?(0, (1 << bits) - 1)

      [value].pack({ 8 => "C", 16 => "n", 32 => "N" }.fetch(bits))
    end

    def self.numbers(parts, *widths) = widths.map { |bits| integer(parts.shift, bits) }.join.b
    def self.b64(parts) = base64_decode(parts.shift(parts.length).join)
    def self.hex_tail(parts) = DNSJSON.unhex(parts.shift(parts.length).join.upcase)
    def self.counted(bytes) = integer(bytes.bytesize, 8) + bytes

    def self.address(text, length)
      ip = IPAddr.new(text)
      raise ConversionError, "wrong IP family or prefix" if text.include?("/") || ip.hton.bytesize != length

      ip.hton
    end

    def self.octets_text(bytes) = bytes.force_encoding(Encoding::ISO_8859_1).encode(Encoding::UTF_8)
    def self.text_octets(text) = text.encode(Encoding::ISO_8859_1).b

    def self.strings_encode(strings)
      strings.flat_map { |s| s.empty? ? ["".b] : s.bytes.each_slice(255).map { |v| v.pack("C*") } }.map { |s| counted(s) }.join.b
    end

    def self.quote(bytes)
      content = bytes.bytes.map do |b|
        if b.between?(32, 126)
          [34, 92].include?(b) ? "\\#{b.chr}" : b.chr
        else
          format("\\%03d", b)
        end
      end.join
      "\"#{content}\""
    end

    def self.parse_strings(text)
      strings = []
      current = nil
      index = 0
      while index < text.bytesize
        byte = text.getbyte(index)
        if current.nil?
          if byte == 34 then current = +"".b
          elsif ![9, 10, 13, 32].include?(byte) then raise ConversionError, "SPF strings must be quoted"
          end
        elsif byte == 34
          strings << current
          current = nil
        elsif byte == 92
          index += 1
          digits = text.byteslice(index, 3)
          raise ConversionError, "unfinished string escape" unless digits && !digits.empty?

          if digits.match?(/\A\d{3}\z/)
            raise ConversionError, "octet escape out of range" if digits.to_i > 255

            current << digits.to_i
            index += 2
          else
            current << text.getbyte(index)
          end
        else
          current << byte
        end
        index += 1
      end
      raise ConversionError, "unclosed or missing SPF string" if current || strings.empty?

      strings
    end

    def self.timestamp(value) = Time.at(value).utc.strftime("%Y%m%d%H%M%S")

    def self.parse_time(text)
      text = required(text)
      return text if text.match?(/\A\d{1,10}\z/)
      raise ConversionError, "invalid DNSSEC timestamp" unless text.match?(/\A\d{14}\z/)

      time = Time.strptime("#{text} +0000", "%Y%m%d%H%M%S %z").utc
      raise ConversionError, "invalid DNSSEC timestamp" unless timestamp(time.to_i) == text

      time.to_i
    end

    def self.bitmap_decode(bytes)
      types = []
      offset = 0
      previous = -1
      while offset < bytes.bytesize
        window, length = bytes.byteslice(offset, 2).unpack("CC")
        raise ConversionError, "invalid type bitmap" unless length&.between?(1, 32) && window > previous && offset + 2 + length <= bytes.bytesize

        bitmap = bytes.byteslice(offset + 2, length)
        raise ConversionError, "noncanonical type bitmap" if bitmap.getbyte(length - 1).zero?

        bitmap.bytes.each_with_index do |value, index|
          8.times { |bit| types << Registry.type((window * 256) + (index * 8) + bit) unless value.nobits?(128 >> bit) }
        end
        previous = window
        offset += length + 2
      end
      types
    end

    def self.bitmap_encode(names)
      names.map { |n| Registry.number(n) }.uniq.sort.group_by { |n| n / 256 }.map do |window, values|
        bitmap = Array.new(((values.last % 256) / 8) + 1, 0)
        values.each { |n| bitmap[(n % 256) / 8] |= 128 >> (n % 8) }
        [window, bitmap.length, *bitmap].pack("C*")
      end.join.b
    end

    def self.base32_encode(bytes)
      bits = bytes.unpack1("B*")
      bits += "0" * ((5 - (bits.length % 5)) % 5)
      bits.scan(/.{5}/).map { |b| BASE32[b.to_i(2)] }.join
    end

    def self.base32_decode(text)
      raise ConversionError, "invalid base32hex" unless text.match?(/\A[0-9A-V]+\z/i)

      bits = text.upcase.chars.map { |c| BASE32.index(c).to_s(2).rjust(5, "0") }.join
      bytes = [bits[0, bits.length / 8 * 8]].pack("B*")
      raise ConversionError, "noncanonical base32hex" unless base32_encode(bytes) == text.upcase

      bytes
    end
  end
end
