# frozen_string_literal: true

module DNSJSON
  module Wire
    class Reader
      def initialize(bytes, **limits)
        raise ParseError, "wire input must be a String" unless bytes.is_a?(String)

        @limits = DNSJSON.validate_limits(limits)
        raise LimitError, "wire input exceeds max_bytes" if bytes.bytesize > @limits[:max_bytes]

        @bytes = bytes.b
        @offset = 0
        @problems = []
        @data = { "messageOctetsHEX" => DNSJSON.hex(@bytes), "headerOctetsHEX" => DNSJSON.hex(@bytes.byteslice(0, 12)) }
      end

      def read(date: nil)
        header
        if @bytes.bytesize >= 12
          total = 0
          SECTIONS.each_with_index do |section, index|
            start = @offset
            records = []
            count = @data.fetch(COUNTS[index])
            count.times do
              if total >= @limits[:max_records]
                problem("record count exceeds max_records")
                break
              end
              total += 1
              record = read_record(question: index.zero?)
              break unless record

              records << record
            end
            @data["#{section}RRs"] = records
            @data["#{section}OctetsHEX"] = DNSJSON.hex(@bytes.byteslice(start, @offset - start))
            next unless index.zero? && !records.empty?

            %w[NAME NAMEHEX TYPE TYPEname CLASS CLASSname].each { |key| @data["Q#{key}"] = records.first[key] }
            @data["compressedQNAME"] = records.first["compressedNAME"]
          end
          if @offset < @bytes.bytesize
            problem("unclaimed trailing bytes")
            @data["additionalOctetsHEX"] += DNSJSON.hex(@bytes.byteslice(@offset..))
          end
        end
        if date
          raise ArgumentError, "date must be a nonnegative Time" unless date.is_a?(Time) && date.to_f >= 0

          @data["dateString"] = date.getutc.iso8601(6)
          @data["dateSeconds"] = date.to_f
        end
        Message.new(@data, problems: @problems, **@limits)
      end

      private

      def problem(reason, offset = @offset) = @problems << Problem.new(offset: offset, reason: reason)

      def header
        @data["ID"] = @bytes.unpack1("n") if @bytes.bytesize >= 2
        if @bytes.bytesize >= 4
          flags = @bytes.byteslice(2, 2).unpack1("n")
          BITS.each { |key, shift| @data[key] = (flags >> shift) & 1 }
          @data["Opcode"] = (flags >> 11) & 15
          @data["RCODE"] = flags & 15
        end
        COUNTS.each_with_index { |key, i| @data[key] = @bytes.byteslice(4 + (i * 2), 2).unpack1("n") if @bytes.bytesize >= 6 + (i * 2) }
        problem("truncated DNS header", @bytes.bytesize) if @bytes.bytesize < 12
        problem("zero questions in DNS message", 4) if @data["QDCOUNT"]&.zero?
        @offset = [12, @bytes.bytesize].min
      end

      def read_record(question:)
        start = @offset
        labels, consumed, compressed = Name.read(@bytes, @offset, max_pointers: @limits[:max_pointers])
        @offset += consumed
        record = { "NAME" => Name.display(labels), "NAMEHEX" => DNSJSON.hex(Name.pack(labels)),
                   "compressedNAME" => { "isCompressed" => compressed ? 1 : 0, "length" => consumed } }
        required = question ? 4 : 10
        raise ConversionError, "truncated resource record header" if @offset + required > @bytes.bytesize

        type, klass = @bytes.byteslice(@offset, 4).unpack("nn")
        record.merge!("TYPE" => type, "TYPEname" => Registry.type(type), "CLASS" => klass, "CLASSname" => Registry.klass(klass))
        @offset += 4
        unless question
          ttl, length = @bytes.byteslice(@offset, 6).unpack("l>n")
          @offset += 6
          record.merge!("TTL" => ttl, "RDLENGTH" => length)
          actual = [length, @bytes.bytesize - @offset].min
          record["RDATAHEX"] = DNSJSON.hex(@bytes.byteslice(@offset, actual))
          if actual < length
            problem("RDLENGTH exceeds available RDATA")
          else
            begin
              value = RData.decode(type, @bytes, @offset, length, max_pointers: @limits[:max_pointers])
              record["rdata#{RData::FORMATS[type]}"] = value unless value.nil?
            rescue ConversionError => e
              problem(e.message)
            end
          end
          @offset += actual
        end
        record["rrOctetsHEX"] = DNSJSON.hex(@bytes.byteslice(start, @offset - start))
        record
      rescue ConversionError => e
        problem(e.message, start)
        @offset = @bytes.bytesize
        nil
      end
    end
  end
end
