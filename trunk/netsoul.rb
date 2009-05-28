begin
  require 'socket'
  require 'yaml'
  require 'digest/md5'
  require 'uri'
  require 'thread'
  require 'logger'
rescue LoadError
  STDERR.puts "Error: #{$!}"
  exit
end

RS_APP_NAME = "RubySoul-Server"
RS_VERSION = "0.7.00"
RS_AUTHOR = "Christian KAKESA"
RS_AUTHOR_EMAIL = "christian.kakesa@gmail.com"

class NetsoulServer
  attr_accessor :socket, :logger

  def initialize(args)
    @args = args||Array.new
    @socket = nil
    @logger = nil
    @socket_num = nil
    @client_host = nil
    @client_port = nil
    @user_from = nil
    @auth_cmd = nil
    @cmd = nil
    @location = nil
    @state = "server"
    @data = get_config()
    @server_timestamp = nil
    @server_timestamp_diff = 0
    get_opt()
    at_exit {  if (@socket ); sock_close() end; if (@logger); @logger.close; end; }
    trap("SIGINT") { exit }
	trap("SIGTERM") { exit }
	start()
  end

  def start
    if not (connect(@data[:login], @data[:socks_password], RS_APP_NAME + " " + RS_VERSION))
      raise "Can't connect to the NetSoul server !"
    else
      @logger.debug "#{RS_APP_NAME} #{RS_VERSION} Started..." if not @logger.nil?
      loop {
      	r,w,e = IO.select([@socket], nil, [@socket])
      	if r
          parse_cmd()
        end
        raise "NetSoul socket is closed !" if @socket.closed?
        raise "Netsoul socket exception !" if e
      }
    end
  end

  def connect(login, pass, user_ag)
    @socket = TCPSocket.new(@data[:server][:host], @data[:server][:port])
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
        str_err = "#{$!} !\n"
        str_err += "Try to build the \"NsToken\" ruby/c extension if you don't.\nSomething like this : \"cd ./lib/kerberos && ruby extconf.rb && make\""
        raise str_err
      end
      tk = NsToken.new
      if not tk.get_token(@data[:login], @data[:unix_password])
        raise "Impossible to retrieve the kerberos token !"
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
    cmd = buff.match(/^(\w+)/)[1]
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
      raise "Login or password incorrect !"
      exit
    when "140"
      ## user identification fail
      raise "User identification failed !"
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
    @socket.puts string
    @logger.debug "[send] : " + string if not @logger.nil?
  end

  def sock_get
    response = @socket.gets.to_s.chomp
    @logger.debug "[gets] : " + response if (response.length > 0 and !@logger.nil?)
    return response
  end

  def sock_close
    sock_send("exit")
    @socket.close
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
    opt_help = false
    opt_info = false
    if @args.length > 0
      @args.each do |opt|
        case opt
        when "help"
          opt_help = true
        when "info"
          opt_info = true
        when "log"
          begin
            if @data[:log_dir].to_s.length > 0
              @logger = Logger.new(@data[:log_dir]+File::SEPARATOR+'rubysoul-server.log', 7, 10240000) if @logger.nil?
            else
              @logger = Logger.new('rubysoul-server.log', 7, 10240000) if @logger.nil?
            end
          rescue
            @logger = nil
          end
        end
      end
      if (opt_help or opt_info)
        if opt_help
          NetsoulServer.print_help
        end
        if opt_info
          NetsoulServer.print_info
        end
        if @logger
          @logger.close
          @logger = nil
        end
        exit
      end
    end
  end
  
  def self.print_info
	STDOUT.puts ' _____       _            _____             _        _____                          '
	STDOUT.puts '|  __ \     | |          / ____|           | |      / ____|                         '
	STDOUT.puts '| |__) |   _| |__  _   _| (___   ___  _   _| |_____| (___   ___ _ ____   _____ _ __ '
	STDOUT.puts '|  _  / | | | \'_ \| | | |\___ \ / _ \| | | | |______\___ \ / _ \ \'__\ \ / / _ \ \'__|'
	STDOUT.puts '| | \ \ |_| | |_) | |_| |____) | (_) | |_| | |      ____) |  __/ |   \ V /  __/ |   '
	STDOUT.puts '|_|  \_\__,_|_.__/ \__, |_____/ \___/ \__,_|_|     |_____/ \___|_|    \_/ \___|_|   '
	STDOUT.puts '                    __/ |                                                           '
	STDOUT.puts '                   |___/                                                            '
	STDOUT.puts
	STDOUT.puts '*************************************************'
    STDOUT.puts '* ' + RS_APP_NAME + ' V' + RS_VERSION + '                       *'
    STDOUT.puts '* ' + RS_AUTHOR + ' <' + RS_AUTHOR_EMAIL + '> *'
    STDOUT.puts '* kakesa_c - ETNA_2008                          *'
    STDOUT.puts '*************************************************'
    STDOUT.puts
  end

  def self.print_help
    STDOUT.puts "***************"
    STDOUT.puts "* Help screen *"
    STDOUT.puts "***************"
    STDOUT.puts "- First you need to put your login, socks password in the config.yml file."
    STDOUT.puts "- For kerberos authentication, you need to put your unix password in the config.yml and build NsToken ruby/c extension in lib/kerberos directory.(ruby extconf.rb && make)"
    STDOUT.puts "- You can run the script like this : \"ruby rubysoul-server.rb\" or \"./rubysoul-server.rb\""
    STDOUT.puts
    STDOUT.puts "* Options"
    STDOUT.puts "\thelp : Print this help message."
    STDOUT.puts "\tinfo : Print author information."
    STDOUT.puts "\tlog  : All message are stored in your_log_dir#{File::SEPARATOR}rubysoul-server.log."
    STDOUT.puts
  end
end

