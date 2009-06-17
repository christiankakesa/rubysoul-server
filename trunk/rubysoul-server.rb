#!/usr/bin/ruby
begin
  require 'netsoul'
rescue LoadError
  $stderr.puts "Error: #{$!}"
  exit
end

begin
  rss = NetsoulServer.new(ARGV)
rescue NSError, NSAuthError
  $stderr.puts "[#{Time.now.to_s}] Error: #{$!}"
  exit
rescue
  $stderr.puts "[#{Time.now.to_s}] Error: #{$!}"
  Kernel.sleep(10)
  retry
end

