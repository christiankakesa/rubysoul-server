#!/usr/bin/ruby
begin
  require 'netsoul'
rescue LoadError
  STDERR.puts "Error: #{$!}"
  exit
end

trap("SIGINT") { exit }
trap("SIGTERM") { exit }
    
begin
  rss = NetsoulServer.new(ARGV)
rescue
  STDERR.puts "[#{Time.now.to_s}] Error: #{$!}"
  sleep 5
  retry
end

