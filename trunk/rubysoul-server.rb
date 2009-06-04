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
  sleep 30
  retry
rescue
  STDERR.puts "[#{Time.now.to_s}] Error: #{$!}"
  sleep 1
  retry
end

