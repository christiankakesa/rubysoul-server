begin
  require 'socket'
  require 'yaml'
  require 'digest/md5'
  require 'uri'
  require 'logger'
rescue LoadError
  STDERR.puts "Error: #{$!}"
  exit
end

RS_APP_NAME = "RubySoul-Server"
RS_VERSION = "0.7.02"
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
    @logger = nil
    @data = get_config()
    get_opt()
    at_exit { if (@socket ); sock_close() end; if (@logger); @logger.close; end; }
    trap("SIGINT") { exit }
    trap("SIGTERM") { exit }
    start()
  end

  def start
    begin
      connect(@data[:login].to_s, @data[:socks_password].to_s, RS_APP_NAME + " " + RS_VERSION)
    rescue
      raise "Can't connect to the NetSoul server !"
    end
    @logger.debug "#{RS_APP_NAME} #{RS_VERSION} Started..." if not @logger.nil?
    loop {
      r,w,e = IO.select([@socket], nil, nil)
      if r
        parse_cmd()
      end
      raise "NetSoul socket is closed !" if @socket.closed?
    }
  end

  def connect(login, pass, user_ag)
    @socket = TCPSocket.new(@data[:server][:host].to_s, @data[:server][:port].to_i)
    buff = sock_get()
    cmd, socket_num, md5_hash, client_host, client_port, server_timestamp = buff.split
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
        str_err += "Try to build the \"NsToken\" ruby/c extension if you don't.\nSomething like this : \"cd ./lib/kerberos && ruby extconf.rb && make\""
        raise NSError, str_err
      end
      tk = NsToken.new
      if not tk.get_token(@data[:login].to_s, @data[:unix_password].to_s)
        raise NSError, "Impossible to retrieve the kerberos token !"
      end
      sock_send("#{auth_cmd}_klog #{tk.token_base64} #{escape(@data[:system])} #{escape(location)} #{escape(@data[:user_group])} #{escape(user_ag)}")
    else
      reply_hash = Digest::MD5.hexdigest("%s-%s/%s%s" % [md5_hash, client_host, client_port, pass])
      sock_send("#{auth_cmd}_log " + login + " " + reply_hash + " " + escape(location) + " " + escape(user_ag))
    end
    parse_cmd()
    sock_send("#{cmd} attach")
    sock_send("#{cmd} state " + STATUS + ":" + server_timestamp.to_s)
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
      raise NSAuthError, "Login or password incorrect !"
    when "140"
      ## user identification fail
      raise NSAuthError, "User identification failed !"
    end
    return true
  end

  def ping(cmd)
    sock_send(cmd.to_s)
  end

  def get_config(filename = File.dirname(__FILE__) + "#{File::SEPARATOR}config.yml")
    config = YAML.load_file(filename);
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

  def get_opt
    opt_help = false
    if @args.length > 0
      @args.each do |opt|
        case opt
        when "--help", "-help", "-h", "-H"
          opt_help = true
        when "--log", "-log", "-l", "-L"
          break if opt_help
          begin
            if @data[:log_dir].to_s.length > 0
              @logger = Logger.new(@data[:log_dir].to_s+File::SEPARATOR+'rubysoul-server.log', 7, 10240000) if @logger.nil?
            else
              @logger = Logger.new('rubysoul-server.log', 7, 10240000) if @logger.nil?
            end
          rescue
            @logger = nil
          end
        end
      end
      if (opt_help)
        NetsoulServer.print_help
        if @logger
          @logger.close
          @logger = nil
        end
        exit
      end
    end
  end

  def self.print_help
    STDOUT.puts ' _____       _            _____             _        _____                          '
    STDOUT.puts '|  __ \     | |          / ____|           | |      / ____|                         '
    STDOUT.puts '| |__) |   _| |__  _   _| (___   ___  _   _| |_____| (___   ___ _ ____   _____ _ __ '
    STDOUT.puts '|  _  / | | | \'_ \| | | |\___ \ / _ \| | | | |______\___ \ / _ \ \'__\ \ / / _ \ \'__|'
    STDOUT.puts '| | \ \ |_| | |_) | |_| |____) | (_) | |_| | |      ____) |  __/ |   \ V /  __/ |   '
    STDOUT.puts '|_|  \_\__,_|_.__/ \__, |_____/ \___/ \__,_|_|     |_____/ \___|_|    \_/ \___|_|   '
    STDOUT.puts '                    __/ |                                                           '
    STDOUT.puts '                   |___/                                                            '
    STDOUT.puts
    STDOUT.puts "- First you need to put your login, socks password in the config.yml file."
    STDOUT.puts "- For kerberos authentication, you need to put your unix password in the config.yml and build NsToken ruby/c extension in lib/kerberos directory.(ruby extconf.rb && make)"
    STDOUT.puts "- You can run the script like this : \"ruby rubysoul-server.rb\" or \"./rubysoul-server.rb\""
    STDOUT.puts
    STDOUT.puts "[Commands options]"
    STDOUT.puts "  --help, -help, -h, -H : Print this help message."
    STDOUT.puts "  --log, -log, -l, -L   : All message are stored in current_or_log_dir#{File::SEPARATOR}rubysoul-server.log."
    STDOUT.puts
    STDOUT.puts '*************************************************'
    STDOUT.puts '* ' + RS_APP_NAME + ' V' + RS_VERSION + '                       *'
    STDOUT.puts '* ' + RS_AUTHOR + ' <' + RS_AUTHOR_EMAIL + '> *'
    STDOUT.puts '* kakesa_c - ETNA_2008                          *'
    STDOUT.puts '*************************************************'
  end
end

