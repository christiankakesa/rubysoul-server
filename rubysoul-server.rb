#!/usr/bin/ruby -w
begin
  require 'socket'
  require 'yaml'
  require 'digest/md5'
  require 'uri'
  require 'thread'
  require 'logger'
  require 'ping'
rescue LoadError
  puts "Error: #{$!}"
  exit
end

RS_APP_NAME = "RubySoul Server"
RS_VERSION = "0.5.50B"
RS_AUTHOR = "Christian KAKESA"
RS_AUTHOR_EMAIL = "christian.kakesa@gmail.com"

class RubySoul
  attr_accessor :socket, :logger
  
  def initialize
    @socket = nil
    @logger = nil
    @socket_num = nil
    @client_host = nil
    @client_port = nil
    @user_from = nil
    @auth_cmd = nil
    @cmd = nil
    @location = nil
    @connect = false
    @state = "server"
    @data = GetConfig()
    @parseThread = nil
    @mutex = Mutex.new
    @timestamp_thread = nil
    @server_timestamp = nil
    @server_timestamp_diff = 0
    begin
      ping_res = Ping.pingecho(@data[:server][:host], 1, @data[:server][:port])
    rescue
      puts '/!\ Netsoul server is not reacheable...'
      retry
    end
    Auth(@data[:login], @data[:pass], RS_APP_NAME + " " + RS_VERSION)
    @parseThread = Thread.new do
      @mutex.synchronize do
      	while (true)
          ParseCMD()
        end
      end
    end
    PrintInfo()
    puts "[" + Time.now.to_s + "] Started..."
    trap("SIGINT") { Exit() }
    trap("SIGTERM") { Exit() }
    @parseThread.join()
  end
  
  def Auth(login, pass, user_ag)
    if not (Connect(login, pass, user_ag))
      puts "Can't connect to the NetSoul server..."
      return false
    else
      @connect = true
      return true
    end
  end
  
  def Connect(login, pass, user_ag)
    if not (@socket)
      @socket = TCPSocket.new(@data[:server][:host], @data[:server][:port])
    end
    if (!@logger and (ARGV[0] == "debug"))
      @logger = Logger.new('logfile.log', 7, 2048000)
    end
    buff = SockGet()
    cmd, @socket_num, md5_hash, @client_host, @client_port, @server_timestamp = buff.split
    @server_timestamp_diff = Time.now.to_i - @server_timestamp.to_i
    reply_hash = Digest::MD5.hexdigest("%s-%s/%s%s" % [md5_hash, @client_host, @client_port, pass])
    @user_from = "ext"
    @auth_cmd = "user"
    @cmd = "cmd"
    @data[:iptable].each do |key, val|
      res = @client_host.match(/^#{val}/)
      if res != nil
        res = "#{key}".chomp
        @location = res
        @user_from = res
        break
      end
    end
    if (@user_from == "ext")
      @auth_cmd = "ext_user"
      @cmd = "user_cmd"
      @location = @data[:location]
    end    
    SockSend("auth_ag ext_user none none")
    ParseCMD()    
    SockSend("ext_user_log " + login + " " + reply_hash + " " + Escape(@location) + " " + Escape(user_ag))
    ParseCMD()
    SockSend("user_cmd attach")
    SockSend("user_cmd state " + @state + ":" +  GetServerTimestamp().to_s)
    return true
  end
  
  def ParseCMD
    buff = SockGet()
    if not (buff.to_s.length > 0)
      SockClose()
      return ""
    end
    cmd = buff.match(/^(\w+)/)[1]
    case cmd.to_s
    when "ping"
      Ping(buff.to_s)
    when "rep"
      Rep(buff)
    else
      return ""
    end
  end
  
  def Rep(cmd)
    msg_num, msg = cmd.match(/^\w+\ (\d{3})\ \-\-\ (.*)/)[1..2]
    case msg_num.to_s
    when "001"
      ## Command unknown
      return true
    when "002"
      ## Nothing to do, all is right
      return true
    when "003"
      ## Bad number of arguments
      return true
    when "033"
      ## Login or password incorrect
      puts "Login or password incorrect"
      Exit()
      return false
    end
    return true
  end
  
  def Ping(cmd)
    SockSend(cmd.to_s)
  end
  
  def GetConfig(filename = File.dirname(__FILE__) + "/config.yml")
    config = YAML::load(File.open(filename));
    return config
  end
  
  def SockSend(string)
    if (@socket)
      @socket.puts string
      if (@logger)
        @logger.debug "[send] : " + string
      end
    end
  end
  
  def SockGet
    if (@socket)
      response = @socket.gets.to_s.chomp
      if (@logger)
        @logger.debug "[gets] : " + response
      end
      return response
    end
  end
  
  def SockClose
    if (@socket )
      @socket.puts "exit"
      @socket.close
    end
  end
  
  def Exit
    at_exit {  if (@socket ); SockClose() end; if (@logger); @logger.close; end; }
    exit
  end
  
  def Escape(str)
    str = URI.escape(str)
    res = URI.escape(str, "\ :'@~\[\]&()=*$!;,\+\/\?")
    return res
  end
  
  def PrintInfo
    puts '*************************************************'
    puts '* ' + RS_APP_NAME + ' V' + RS_VERSION + '                      *'
    puts "* #{RS_AUTHOR} <#{RS_AUTHOR_EMAIL}> *"
    puts '* kakesa_c - ETNA_2008                          *'
    puts '*************************************************'
  end

  def GetServerTimestamp
    return Time.now.to_i - @server_timestamp_diff.to_i
  end
end

begin
  rss = RubySoul.new
rescue IOError, Errno::ENETRESET, Errno::ESHUTDOWN, Errno::ETIMEDOUT, Errno::ECONNRESET, Errno::ENETDOWN, Errno::EINVAL, Errno::ECONNABORTED, Errno::EIO, Errno::ECONNREFUSED, Errno::ENETUNREACH, Errno::EFAULT, Errno::EHOSTUNREACH, Errno::EINTR, Errno::EBADF
  puts "Error: #{$!}"
  retry
rescue
  puts "Unknown error, you can send email to the author at : #{RS_AUTHOR_EMAIL}"
  puts "Error: #{$!}"
  exit
end
