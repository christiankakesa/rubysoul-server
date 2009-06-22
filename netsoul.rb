begin
  require 'socket'
  require 'yaml'
  require 'digest/md5'
  require 'uri'
  require 'lib/reactor'
rescue LoadError
  $stderr.puts "Error: #{$!}"
  exit
end

RS_APP_NAME = "RubySoul-Server"
RS_VERSION = "0.7.05"
RS_AUTHOR = "Christian KAKESA"
RS_AUTHOR_EMAIL = "christian.kakesa@gmail.com"
STATUS = "server"

class NSError < StandardError; end
class NSAuthError < StandardError; end

class NetsoulServer
  attr_accessor :socket, :logger

  def initialize(args)
    @args = args||Array.new
    @socket = nil
    @config_file = nil
    get_opt()
    @data = get_config()
    at_exit { if (@socket); sock_close(); end; NetsoulServer.print_help(); }
    trap('INT'  ) { exit }
    trap('TERM' ) { exit }
    trap('KILL' ) { exit }
    start()
  end

  def start
    connect(@data[:login].to_s, @data[:socks_password].to_s, RS_APP_NAME + " " + RS_VERSION)
    $stdout.puts "#{RS_APP_NAME} #{RS_VERSION} Started..." if $DEBUG
    reactor = Reactor::Base.new
    reactor.attach(:read, @socket) do
      if (@socket.closed? || @socket.nil?)
        raise "Socket is closed or not available"
      end
      begin
        parse_cmd()
      rescue
        raise "Error in parse command. #{$!}"
      end
    end
    reactor.run()
  end

  def connect(login, pass, user_ag)
    @socket = TCPSocket.new(@data[:server][:host].to_s, @data[:server][:port].to_i)
    buff = sock_get()
    salut, socket_num, md5_hash, client_host, client_port, server_timestamp = buff.split
    user_from = "ext"
    auth_cmd = "user"
    cmd = "cmd"
    @data[:iptable].each do |key, val|
      res = client_host.match(/^#{val}/)
      if res != nil
        res = "#{key}".chomp
        location = res
        user_from = res
        break
      end
    end
    if (user_from == "ext")
      auth_cmd = "ext_user"
      cmd = "user_cmd"
      location = @data[:location].to_s
    end
    sock_send("auth_ag #{auth_cmd} none -")
    parse_cmd()
    if @data[:unix_password].to_s.length > 0
      begin
        require 'lib/kerberos/NsToken'
      rescue LoadError
        str_err = "#{$!} !\n"
        str_err += "Try to build the \"NsToken\" ruby/c extension if you don't.\n"
        str_err += "Something like this : \"cd ./lib/kerberos && ruby extconf.rb && make\""
        raise NSError.new(str_err)
      end
      tk = NsToken.new
      if not tk.get_token(@data[:login].to_s, @data[:unix_password].to_s)
        raise NSError.new("Impossible to retrieve the kerberos token !")
      end
      sock_send("#{auth_cmd}_klog #{tk.token_base64.slice(0, 812)} #{escape(@data[:system])} #{escape(location)} #{escape(@data[:user_group])} #{escape(user_ag)}")
    else
      reply_hash = Digest::MD5.hexdigest("#{md5_hash}-#{client_host}/#{client_port}#{pass}")
      sock_send("#{auth_cmd}_log #{login} #{reply_hash} #{escape(location)} #{escape(user_ag)}")
    end
    parse_cmd()
    sock_send("#{cmd} attach")
    sock_send("#{cmd} state #{STATUS}:#{server_timestamp.to_s}")
  end

  def parse_cmd
    buff = sock_get()
    if buff.to_s.length > 0
      cmd = buff.match(/^(\w+)/)[1]
    else
      raise "Socket buffer is empty"
    end
    case cmd.to_s
    when "ping"
      ping(buff.to_s)
    when "rep"
      rep(buff)
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
      raise NSAuthError.new("Login or password incorrect !")
    when "140"
      ## user identification fail
      raise NSAuthError.new("User identification failed !")
    end
    return true
  end

  def ping(cmd)
    sock_send(cmd.to_s)
  end

  def get_config(filename = File.dirname(__FILE__) + "#{File::SEPARATOR}config.yml")
  	config_file = @config_file||filename
    fd = File.open(config_file, 'r')
    config = YAML.load(fd)
    fd.close
    return config
  end

  def sock_send(string)
    @socket.puts string
    $stdout.puts "#{Time.now}|[send] : #{string}" if $DEBUG
  end

  def sock_get
    response = @socket.gets.to_s.chomp
    $stdout.puts "#{Time.now}|[gets] : #{response}" if $DEBUG
    return response
  end

  def sock_close
    sock_send("exit")
    @socket.close
  end

  def escape(str)
    res = URI.escape(str, Regexp.new("#{URI::PATTERN::ALNUM}[:graph:][:punct:][:cntrl:][:print:][:blank:]", false))
    res = URI.escape(res, Regexp.new("[^#{URI::PATTERN::ALNUM}]", false))
    return res
  end

  def get_opt
    if @args.length > 0
      while opt = @args.shift do
      	case opt
        when "--help", "-help", "-h", "-H"
          NetsoulServer.print_help
          exit
        when "--config", "-config", "-c", "-C"
        	@config_file = @args.shift||""
        	raise NSError.new("Config file does not exists") if not FileTest.exist?(@config_file)
        else
          $stderr.puts "Unknwon paramater : #{opt}"
        end
      end
      
    end
  end

  def self.print_help
    $stdout.puts
    $stdout.puts ' _____       _            _____             _        _____                          '
    $stdout.puts '|  __ \     | |          / ____|           | |      / ____|                         '
    $stdout.puts '| |__) |   _| |__  _   _| (___   ___  _   _| |_____| (___   ___ _ ____   _____ _ __ '
    $stdout.puts '|  _  / | | | \'_ \| | | |\___ \ / _ \| | | | |______\___ \ / _ \ \'__\ \ / / _ \ \'__|'
    $stdout.puts '| | \ \ |_| | |_) | |_| |____) | (_) | |_| | |      ____) |  __/ |   \ V /  __/ |   '
    $stdout.puts '|_|  \_\__,_|_.__/ \__, |_____/ \___/ \__,_|_|     |_____/ \___|_|    \_/ \___|_|   '
    $stdout.puts '                    __/ |                                                           '
    $stdout.puts '                   |___/                                                            '
    $stdout.puts
    $stdout.puts "-First you need to put your login, socks password in the config.yml file."
    $stdout.puts "-For kerberos authentication, you need to put your unix password in the config.yml "
    $stdout.puts " and build NsToken ruby/c extension in lib/kerberos directory.(ruby extconf.rb && make)"
    $stdout.puts "-You can run the script like this : \"ruby rubysoul-server.rb\" or \"./rubysoul-server.rb\""
    $stdout.puts
    $stdout.puts "[Commands options]"
    $stdout.puts "  --help, -help, -h, -H     : Print this help message."
    $stdout.puts "  --config, -config, -c, -C : Define config file."
    $stdout.puts
    $stdout.puts '*************************************************'
    $stdout.puts '* ' + RS_APP_NAME + ' V' + RS_VERSION + '                       *'
    $stdout.puts '* ' + RS_AUTHOR + ' <' + RS_AUTHOR_EMAIL + '> *'
    $stdout.puts '* kakesa_c - ETNA_2008                          *'
    $stdout.puts '*************************************************'
  end
end

