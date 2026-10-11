# frozen_string_literal: true

module DNSJSON
  module Wire
    module Name
      def self.read(bytes, offset, max_pointers: 128)
        labels = []
        visited = {}
        cursor = offset
        consumed = 0
        jumped = false
        loop do
          raise ConversionError, "truncated name at #{cursor}" if cursor >= bytes.bytesize
          raise ConversionError, "compression loop at #{cursor}" if visited[cursor]

          visited[cursor] = true
          size = bytes.getbyte(cursor)
          if size >= 192
            raise ConversionError, "truncated compression pointer" if cursor + 1 >= bytes.bytesize

            target = ((size & 63) << 8) | bytes.getbyte(cursor + 1)
            raise ConversionError, "compression pointer must point backwards" if target >= cursor

            max_pointers -= 1
            raise ConversionError, "name exceeds max_pointers" if max_pointers.negative?

            consumed += 2 unless jumped
            jumped = true
            cursor = target
          elsif size >= 64
            raise ConversionError, "unsupported label encoding"
          else
            consumed += size + 1 unless jumped
            break if size.zero?
            raise ConversionError, "truncated label" if cursor + size >= bytes.bytesize

            labels << bytes.byteslice(cursor + 1, size)
            raise ConversionError, "expanded name exceeds 255 bytes" if labels.sum(&:bytesize) + labels.length + 1 > 255

            cursor += size + 1
          end
        end
        [labels, consumed, jumped]
      end

      def self.display(labels)
        return "." if labels.empty?

        result = labels.map do |label|
          label.bytes.map do |byte|
            case byte
            when 46, 92 then "\\#{byte.chr}"
            when 33..126 then byte.chr
            else format("\\%03d", byte)
            end
          end.join
        end.join(".")
        "#{result}."
      end

      def self.encode(text)
        raise ConversionError, "name must be an ASCII string" unless text.is_a?(String) && text.ascii_only?
        return "\0".b if text == "." || text.empty?

        labels = []
        label = +"".b
        index = 0
        while index < text.bytesize
          byte = text.getbyte(index)
          if byte == 92
            index += 1
            raise ConversionError, "unfinished name escape" if index == text.bytesize

            digits = text.byteslice(index, 3)
            if digits.match?(/\A\d{3}\z/)
              raise ConversionError, "name escape exceeds one octet" if digits.to_i > 255

              label << digits.to_i
              index += 2
            else
              label << text.getbyte(index)
            end
          elsif byte == 46
            raise ConversionError, "empty interior name label" if label.empty?

            labels << label
            label = +"".b
          else
            label << byte
          end
          index += 1
        end
        labels << label unless label.empty?
        pack(labels)
      end

      def self.pack(labels)
        raise ConversionError, "label exceeds 63 bytes" if labels.any? { |s| s.bytesize > 63 }

        result = labels.map { |s| s.bytesize.chr.b + s.b }.join.b + "\0".b
        raise ConversionError, "name exceeds 255 bytes" if result.bytesize > 255

        result
      end
    end
  end
end
