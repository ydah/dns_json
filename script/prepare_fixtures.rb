# frozen_string_literal: true

require "json"
require "digest"
require "fileutils"
require "tempfile"
module ReferenceFixtures
  ROOT = File.expand_path("..", __dir__)
  SOURCES = JSON.parse(File.read(File.join(__dir__, "sources.json"))).freeze
  def self.fetch(name)
    source = SOURCES.fetch(name)
    directory = File.join(ROOT, "tmp", name.end_with?(".txt") ? "rfc" : "registry", "sources")
    FileUtils.mkdir_p(directory)
    path = File.join(directory, name)
    unless File.file?(path)
      Tempfile.create("download", directory) do |file|
        success = system("curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--proto-redir", "=https",
                         "--retry", "3", "--connect-timeout", "10", "--max-time", "60", source.fetch("url"), "--output", file.path)
        raise "Download failed: #{name}" unless success
        raise "Checksum mismatch: #{name}" unless Digest::SHA256.file(file.path).hexdigest == source.fetch("sha256")

        File.rename(file.path, path)
      end
    end
    raise "Checksum mismatch: #{name}" unless Digest::SHA256.file(path).hexdigest == source.fetch("sha256")

    path
  end

  def self.object(text, start)
    depth = 0
    quoted = false
    escaped = false
    text[start..].each_char.with_index do |char, index|
      if quoted
        if escaped then escaped = false
        elsif char == "\\" then escaped = true
        elsif char == '"' then quoted = false
        end
      elsif char == '"' then quoted = true
      elsif char == "{" then depth += 1
      elsif char == "}"
        depth -= 1
        return text[start, index + 1] if depth.zero?
      end
    end
    raise "Unclosed RFC example"
  end

  def self.prepare
    source = File.read(fetch("rfc8427.txt"))
    section = source.split("5.1.  Example of the Format of a DNS Query", 2).last
    examples = { "5.1-query" => object(section, section.index('{ "ID"')) }
    section = source.split("5.2.  Example of the Format of a Paired DNS Query and Response", 2).last
    start = section.index(/\{\s*"queryMessage"/)
    examples["5.2-pair"] = object(section, start)
    # Extract the separate rrSet alternative as its own object without copying source text into Git.
    start = section.index(/\{\s*"NAME"/, section.index("rrSet:"))
    examples["5.2-rrset"] = object(section, start)
    directory = File.join(ROOT, "tmp/rfc/fixtures")
    FileUtils.mkdir_p(directory)
    examples.each { |name, text| File.write(File.join(directory, "#{name}.json"), "#{JSON.pretty_generate(JSON.parse(text))}\n") }
    File.write(File.join(directory, "LICENSE"), <<~NOTICE)
      RFC Code Components used only for conformance testing.
      Copyright (c) 2018 IETF Trust and the persons identified as authors of the code. All rights reserved.
      Redistribution and use in source and binary forms, with or without modification, is permitted pursuant to,
      and subject to the license terms contained in, the Revised BSD License set forth in Section 4.c of the
      IETF Trust's Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info).
      Source and full notices: ../sources/rfc8427.txt
      Examples retain the inconsistent ANCOUNT from RFC 8427 section 5.2 (erratum 5570, held for update).
    NOTICE
    puts "Prepared #{examples.length} RFC examples in ignored tmp/rfc/fixtures"
  end
end
ReferenceFixtures.prepare if $PROGRAM_NAME == __FILE__
