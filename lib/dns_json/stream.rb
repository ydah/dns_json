# frozen_string_literal: true

module DNSJSON
  module Stream
    class Writer
      def initialize(io, profile: Profile::FULL)
        @io = io
        @profile = profile
      end

      def <<(message)
        @io.write("\x1e#{message.to_json(profile: @profile)}\n")
        self
      end
    end

    class Reader
      include Enumerable

      attr_reader :problems, :dropped_problems

      def initialize(io, strict: false, max_json_bytes: LIMITS[:max_json_bytes], max_problems: 1000, **options)
        @io = io
        @strict = strict
        @max_bytes = max_json_bytes
        @options = options
        @problems = []
        raise ArgumentError, "limits must be positive integers" unless [max_json_bytes, max_problems].all? { |n| n.is_a?(Integer) && n.positive? }

        @max_problems = max_problems
        @dropped_problems = 0
      end

      def each(&block)
        return enum_for(:each) unless block_given?

        buffer = +"".b
        started = false
        oversized = false
        index = 0
        while (chunk = @io.read(4096)) && !chunk.empty?
          chunk.each_byte do |byte|
            if byte == 30
              consume(buffer, index, &block) if started && !buffer.strip.empty? && !oversized
              index += 1 if started
              buffer = +"".b
              started = true
              oversized = false
            elsif started && !oversized
              buffer << byte
              if buffer.bytesize > @max_bytes
                report(LimitError.new("sequence element exceeds max_json_bytes"), index)
                buffer = +"".b
                oversized = true
              end
            elsif !started && ![9, 10, 13, 32].include?(byte)
              report(ParseError.new("content before first record separator"), index)
              started = true
              oversized = true
            end
          end
        end
        consume(buffer, index, &block) if started && !buffer.strip.empty? && !oversized
        self
      end

      private

      def consume(buffer, index)
        message = begin
          DNSJSON.parse(buffer, max_json_bytes: @max_bytes, **@options)
        rescue Error => e
          report(e, index)
          nil
        end
        yield message if message
      end

      def report(error, index)
        raise error if @strict

        if @problems.length < @max_problems
          @problems << Problem.new(offset: index, reason: error.message)
        else
          @dropped_problems += 1
        end
      end
    end
  end
end
