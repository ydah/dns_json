# frozen_string_literal: true

module DNSJSON
  module Wire
    class Writer
      def initialize(data, **limits)
        @data = data
        @limits = DNSJSON.validate_limits(limits)
        @record_count = 0
      end

      def write
        Message.new(@data, **@limits)
        return bounded(DNSJSON.unhex(@data["messageOctetsHEX"])) if @data.key?("messageOctetsHEX")

        sections = SECTIONS.map { |section| expand(@data.fetch("#{section}RRs", [])) }
        if sections[0].empty? && (@data.key?("QNAME") || @data.key?("QNAMEHEX"))
          sections[0] = [@data.each_with_object({}) { |(k, v), h| h[k.delete_prefix("Q")] = v if k.start_with?("Q") && k != "QDCOUNT" }]
        end
        raise LimitError, "record count exceeds max_records" if sections.sum(&:length) > @limits[:max_records]

        id = required(@data, "ID")
        flags = BITS.sum { |key, shift| [true, 1].include?(@data.fetch(key, 0)) ? 1 << shift : 0 }
        flags |= @data.fetch("Opcode", 0) << 11
        flags |= @data.fetch("RCODE", 0)
        counts = COUNTS.each_with_index.map { |key, i| @data.fetch(key, sections[i].length) }
        result = [id, flags, *counts].pack("n6")
        sections.each_with_index do |records, index|
          records.each do |record|
            result << encode_record(record, question: index.zero?)
            bounded(result)
          end
        end
        bounded(result)
      end

      private

      def bounded(bytes)
        raise LimitError, "wire output exceeds max_bytes" if bytes.bytesize > @limits[:max_bytes]

        bytes
      end

      def required(data, key)
        raise ConversionError, "missing #{key}" unless data.key?(key)

        data[key]
      end

      def expand(records)
        records.flat_map do |record|
          count = record.key?("rrSet") ? record["rrSet"].length : 1
          @record_count += count
          raise LimitError, "record count exceeds max_records" if @record_count > @limits[:max_records]

          record.key?("rrSet") ? record["rrSet"].map { |entry| record.except("rrSet").merge(entry) } : [record]
        end
      end

      def code(record, key, kind)
        record.key?(key) ? record[key] : Registry.number(required(record, "#{key}name"), kind)
      end

      def encode_record(record, question:)
        name = if record.key?("NAMEHEX")
                 bytes = DNSJSON.unhex(record["NAMEHEX"])
                 labels, size = Name.read(bytes, 0, max_pointers: 0)
                 raise ConversionError, "excess NAMEHEX data" unless size == bytes.bytesize

                 Name.pack(labels)
               else
                 Name.encode(required(record, "NAME"))
               end
        type = code(record, "TYPE", :type)
        klass = code(record, "CLASS", :class)
        result = name + [type, klass].pack("nn")
        return result if question

        ttl = required(record, "TTL")
        # Prefer structured RDATA on reconstruction: captured RDATAHEX can contain obsolete compression offsets.
        member = "rdata#{RData::FORMATS[type]}"
        rdata = if record.key?(member)
                  RData.encode(type, record[member])
                else
                  DNSJSON.unhex(required(record, "RDATAHEX"))
                end
        raise ConversionError, "RDATA exceeds 65535 bytes" if rdata.bytesize > 65_535

        result + [ttl, record.key?(member) ? rdata.bytesize : record.fetch("RDLENGTH", rdata.bytesize)].pack("l>n") + rdata
      end
    end
  end
end
