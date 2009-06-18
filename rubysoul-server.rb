#!/usr/bin/ruby
begin
  require 'netsoul'
rescue LoadError
  STDERR.puts "Error: #{$!}"
  exit
end

begin
  rss = NetsoulServer.new(ARGV)
rescue NSError, NSAuthError
  STDERR.puts "[#{Time.now.to_s}] Error: #{$!}"
rescue
  STDERR.puts "[#{Time.now.to_s}] Error: #{$!}"
  retry
end

