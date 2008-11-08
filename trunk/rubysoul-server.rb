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
RS_VERSION = "0.6.20"
RS_AUTHOR = "Christian KAKESA"
RS_AUTHOR_EMAIL = "christian.kakesa@gmail.com"

class RubySoulServer
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
    @data = get_config()
    @parse_thread = nil
    @mutex = Mutex.new
    @timestamp_thread = nil
    @server_timestamp = nil
    @server_timestamp_diff = 0
    get_opt()
    begin
      ping_res = Ping.pingecho(@data[:server][:host], 1, @data[:server][:port])
    rescue
      puts '[#{Time.now.to_s}] /!\ Netsoul server is not reacheable...'
      retry
    end
    auth()
    @parse_thread = Thread.new do
      @mutex.synchronize do
      	while (true)
          parse_cmd()
        end
      end
    end
    puts "[#{Time.now.to_s}] #{RS_APP_NAME} #{RS_VERSION} Started..."
    at_exit {  if (@socket ); sock_close() end; if (@logger); @logger.close; end; }
    trap("SIGINT") { exit }
    trap("SIGTERM") { exit }
    @parse_thread.join()
  end
  
  def auth
    if not (connect(@data[:login], @data[:socks_password], RS_APP_NAME + " " + RS_VERSION))
      puts "[#{Time.now.to_s}] Can't connect to the NetSoul server..."
      return false
    else
      @connect = true
      return true
    end
  end
  
  def connect(login, pass, user_ag)
    if not (@socket)
      @socket = TCPSocket.new(@data[:server][:host], @data[:server][:port])
    end
    buff = sock_get()
    cmd, @socket_num, md5_hash, @client_host, @client_port, @server_timestamp = buff.split
    @server_timestamp_diff = Time.now.to_i - @server_timestamp.to_i
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
    sock_send("auth_ag #{@auth_cmd} none -")
    parse_cmd()
    if @data[:unix_password].length > 0
      begin
        require 'lib/kerberos/NsToken'
      rescue LoadError
        puts "Error: #{$!}"
        puts "Build the \"NsToken\" ruby/c extension if you don't.\nSomething like this : \"cd ./lib/kerberos && ruby extconf.rb && make\""
        exit
      end
      tk = NsToken.new
      if not tk.get_token(@data[:login], @data[:unix_password])
        puts "Impossible to retrieve the kerberos token"
        exit
      end
      sock_send("#{@auth_cmd}_klog " + tk.token_base64 + " #{escape(@data[:system])} #{escape(@location)}  #{escape(@data[:user_group])} #{escape(user_ag)}")
    else
      reply_hash = Digest::MD5.hexdigest("%s-%s/%s%s" % [md5_hash, @client_host, @client_port, pass])
      sock_send("#{@auth_cmd}_log " + login + " " + reply_hash + " " + escape(@location) + " " + escape(user_ag))
    end
    parse_cmd()
    sock_send("#{@cmd} attach")
    sock_send("#{@cmd} state " + @state + ":" +  get_server_timestamp().to_s)
    return true
  end

  def parse_cmd
    buff = sock_get()
    if not (buff.to_s.length > 0)
      return ""
    end
    cmd = buff.match(/^(\w+)/)[1]
    case cmd.to_s
    when "ping"
      ping(buff.to_s)
    when "rep"
      rep(buff)
    else
      return ""
    end
  end
  
  def rep(cmd)
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
      puts "[#{Time.now.to_s}] Login or password incorrect"
      exit
    when "140"
      ## user identification fail
      puts "[#{Time.now.to_s}] User identification failed"
      exit
    end
    return true
  end
  
  def ping(cmd)
    sock_send(cmd.to_s)
  end
  
  def get_config(filename = File.dirname(__FILE__) + "/config.yml")
    config = YAML::load(File.open(filename));
    return config
  end
  
  def sock_send(string)
    if (@socket)
      @socket.puts string
      if (@logger)
        @logger.debug "[send] : " + string
      end
    end
  end
  
  def sock_get
    if (@socket)
      response = @socket.gets.to_s.chomp
      if (@logger)
        @logger.debug "[gets] : " + response
      end
      return response
    end
  end
  
  def sock_close
    if (@socket )
      sock_send("#{@cmd} state exit:" +  get_server_timestamp().to_s)
      @socket.close
    end
  end

  def escape(str)
    str = URI.escape(str)
    res = URI.escape(str, "\ :'@~\[\]&()=*$!;,\+\/\?")
    return res
  end
  
  def get_server_timestamp
    return Time.now.to_i - @server_timestamp_diff.to_i
  end

  def get_opt
    if ARGV.length > 0
      ARGV.each do |opt|
        case opt
        when "help"
          RubySoulServer.print_help
        when "info"
          RubySoulServer.print_info
        when "log"
          @logger = Logger.new('logfile.log', 7, 2048000)
        end
      end
    end
  end

  def self.print_info
    puts '*************************************************'
    puts '* ' + RS_APP_NAME + ' V' + RS_VERSION + '                      *'
    puts '* ' + RS_AUTHOR + ' <' + RS_AUTHOR_EMAIL + '> *'
    puts '* kakesa_c - ETNA_2008                          *'
    puts '*************************************************'
    puts
  end

  def self.print_help
    puts "***************"
    puts "* Help screen *"
    puts "***************"
    puts "- First you need to put your login, socks password in the config.yml file."
    puts "- For kerberos authentication, you need to put your unix password in the config.yml and build NsToken ruby/c extension in lib/kerberos directory.(ruby extconf.rb && make)"
    puts "- You can run the script like this : \"ruby rubysoul-server.rb\" or \"./rubysoul-server.rb\""
    puts
  end
end

begin
  rss = RubySoulServer.new
rescue IOError, Errno::ENETRESET, Errno::ESHUTDOWN, Errno::ETIMEDOUT, Errno::ECONNRESET, Errno::ENETDOWN, Errno::EINVAL, Errno::ECONNABORTED, Errno::EIO, Errno::ECONNREFUSED, Errno::ENETUNREACH, Errno::EFAULT, Errno::EHOSTUNREACH, Errno::EINTR, Errno::EBADF
  puts "[#{Time.now.to_s}] Error: #{$!}"
  #TODO: ping while server is restarting, whenn done continue
  retry
rescue
  puts "[#{Time.now.to_s}] Unknown error, you can send email to the author at : #{RS_AUTHOR_EMAIL}"
  puts "[#{Time.now.to_s}] Error: #{$!}"
  exit
end
