#!/usr/bin/ruby
begin
  require 'netsoul'
rescue LoadError
  $stderr.puts "Error: #{$!}"
  exit
end

rss = NetsoulServer.new(ARGV)

