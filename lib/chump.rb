#!/usr/bin/env ruby

# =============================================================================
# chump.rb: Expect-like utility for automating interactive sessions
#
# Steve Shreeve <steve.shreeve@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# =============================================================================

require 'socket'

STDIN.sync = STDOUT.sync = STDERR.sync = true
UNIX = RUBY_PLATFORM =~ /linux|darwin/

class IO
  def self.socketpair(sync=true)
    if UNIX
      one, two = UNIXSocket.socketpair
    else
      tcp = TCPServer.new('127.0.0.1', 0)
      one = TCPSocket.new('127.0.0.1', tcp.addr[1])
      two = tcp.accept and tcp.close
    end
    one.sync = two.sync = true if sync
    [one, two]
  end
end

class Chump
  attr_accessor :slow

  def self.connect(url, opts={})
    scheme, _, target, *info = url.split('/') # scheme://target/info
    target =~ /^(?:(\w+)(?::([^@]+))?@)?(?:([^:]+)?(?::(\d+))?)$/
    user, pass, host, port = $1,$2,$3,$4 # user:pass@host:port

    opts[:url ] = "#{scheme}//" << [user, host].compact.join('@')
    opts[:url ] << ":#{port}" if host && port
    opts[:url ] << ['', *info].compact.join('/')
    opts[:info] = info unless info.empty?

    case scheme
      when 'spawn:' then spawn(target, opts)
      when 'ssh:'   then ssh(host, port, user, pass, opts)
      when 'tcp:'   then tcp(host, port, user, pass, opts)
      else abort "can't parse #{url.inspect}"
    end
  end

  def self.spawn(cmd=nil, opts={})
    io, child_io = IO.socketpair

    if UNIX
      require 'pty'
      cmd = ENV['SHELL'].dup if !cmd || cmd.empty?
      cmd << '; cat -' # hack to keep program running, anything better?
      reader, writer, pid = PTY.spawn(cmd); reader.sync = writer.sync = true
      Thread.new { child_io.syswrite(reader.sysread(1 << 16)) while true }
      Thread.new { writer.syswrite(child_io.sysread(1 << 16)) while true }
      at_exit do
        Process.kill(9, pid)
      end
    else
      require 'win32/process'
      child = Process.create(
        'app_name' => "cmd /k #{cmd}",
        'process_inherit' => true, #!# is this needed?
        'thread_inherit'  => true, #!# is this needed?
        'startup_info' => {
          'stdin'  => child_io,
          'stdout' => child_io,
          'stderr' => File.open('nul', 'wb') # ignore STDERR (what about sync? close?)
        }
      )
      at_exit do
        Process.TerminateProcess(child.process_handle, child.process_id)
        Process.CloseHandle(child.process_handle)
      end
      child_io.close
    end

    opts[:io] ? io : new(io, opts)
  end

  def self.ssh(host, port=nil, user=nil, pass=nil, cmd=nil, opts={})
    io, child_io = IO.socketpair

    require 'net/ssh'
    ENV['HOME'] ||= ENV['USERPROFILE'] unless UNIX
    options = {}; options[:pass] = pass if pass; options[:port] = port if port
    ssh = Net::SSH.start(host||'localhost', user||ENV['USER']||ENV['USERNAME'], options)
    ssh.open_channel do |channel|
      channel.request_pty do |ch, success|
        raise "can't get pty" unless success
      end
      channel.send_channel_request "shell" do |ch, success|
        raise "can't start shell" unless success
        ch.send_data "#{cmd}\r" if cmd && !cmd.empty?
        Thread.new do
          loop do
            if select([child_io], nil, nil, 0.25)
              data = child_io.sysread(1 << 16) or raise "can't read from child_io"
              ch.send_data(data)
              ssh.process
            end
          end
        end
      end
      channel.on_data do |ch, data|
        child_io.syswrite(data)
      end
    end
    Thread.new { ssh.loop }

    opts[:io] ? io : new(io, opts)
  end

  def self.tcp(host, port, user=nil, pass=nil, opts={})
    user,opts = nil,user if user.is_a?(Hash) && pass==nil && opts.empty? # allow short calls
    host ||= "127.0.0.1"
    port ||= 23
    pass ||= "" if user

    io = TCPSocket.new(host, port.to_i)

    opts[:auth] ||= {
      # /\xFF\xFD(.)/ => proc { [:pure, "\xFF\xFC#{$1}" ] }, # reject these (do -> wont)
      # /\xFF\xFB(.)/ => proc { [:pure, "\xFF\xFE#{$1}" ] }, # accept these (will -> dont)
      /Log ?in|User ?name/i => [user],
      /Pass ?word/i => pass,
      :else => nil,
    } if user && pass

    opts[:io] ? io : new(io, opts)
  end

  def initialize(io, opts={})
    opts.empty? or opts.each {|k,v| opts[k.to_sym] ||= v if k.is_a?(String)}
    @live = opts.has_key?(:live) ? opts[:live] : true    # live reads
    @nocr = opts.has_key?(:nocr) ? opts[:nocr] : true    # strip "\r"
    @ansi = opts.has_key?(:ansi) ? opts[:ansi] : false   # allow ANSI escapes => for GT.M, but checkout "U $P:(NOECHO)"
    @show = opts.has_key?(:show) ? opts[:show] : false   # show matches
    @echo = opts.has_key?(:echo) ? opts[:echo] : false   # echo sends
    @wait = opts.has_key?(:wait) ? opts[:wait] : nil     # sleep times
    @bomb = opts.has_key?(:bomb) ? opts[:bomb] : true    # bomb on slow timeout
    @slow = opts.has_key?(:slow) ? opts[:slow] : 10      # slow timeout
    @fast = opts.has_key?(:fast) ? opts[:fast] : 0.25    # fast timeout
    @size = opts.has_key?(:size) ? opts[:size] : 1 << 16 # buffer size
    @line = opts.has_key?(:line) ? opts[:line] : "\r"    # line terminator
    @buff = ''

    @start = Time.now
    @sleep = 0.0
    @final = @start

    @io = io.is_a?(String) ? self.class.connect(io,opts.update(:io=>true)) : io
    @io.sync = true

    chat(opts.delete(:auth)) if opts[:auth] # authenticate if requested
    chat(opts.delete(:init)) if opts[:init] # initialize if requested
  end

  def chat(*list)
    return self if list.empty?
    item = nil
    back = nil
    talk = false
    fast = false
    list.each do |item|
      loop do
        case item
        when false, Symbol # notifier
          back = item
          case back
            when :redo then break
            else return back
          end
          break
        when true, nil # continuer
          back = item
          talk = !talk if item.nil?
          break
        when String, Fixnum, Float # [literal]
          item = item.to_s
          if talk # talker
            send(item)
            back = item
            talk = false
            break
          elsif index = @buff.index(item) # comparer
            @last = item # save for future reference
            back = @buff.slice!(0..(index + item.size - 1))
            print back.tr("\r",'') if @show
            talk = true
            break
          end
        when Regexp # matcher
          if match = @buff.match(item)
            @last = match[1] || match[0] # save for future reference
            @buff = match.post_match
            back = [match.pre_match + match.to_s, *match.to_a[1..-1]]
            print back.first.tr("\r",'') if @show
            talk = true
            break
          else
            talk = false
          end
        when Hash # multiplexer
          item.each do |key, val|
            key, val =  '', item[:else] if fast
            case key
            when :else # insurer
              next
            when Symbol # yielder
              case val
              when String, Fixnum, Float # comparer
                val = val.to_s
                if index = @buff.index(val)
                  back = @buff.slice!(0..(index + val.size - 1))
                  print back.tr("\r",'') if @show
                  back = yield(key, back) if block_given?
                  break
                end
              when Regexp # matcher
                if match = @buff.match(val)
                  @buff = match.post_match
                  back = [match.pre_match + match.to_s, *match.to_a[1..-1]]
                  print back.first.tr("\r",'') if @show
                  back = yield(key, back) if block_given?
                  break
                end
              when Array, Proc, Hash # indexer
                # processed elsewhere
              else
                raise "Hash symbols don't support #{val.class} matchers"
              end
            when String, Fixnum, Float, Regexp # comparer/matcher (ugly, but shares actions)
              key = key.to_s unless regx = key.is_a?(Regexp)
              if fast
                back = :else
              elsif !regx && index = @buff.index(key)
                back = @buff.slice!(0..(index + key.size - 1))
                print back.tr("\r",'') if @show
              elsif regx && match = @buff.match(key)
                @buff = match.post_match
                back = [match.pre_match + match.to_s, *match.to_a[1..-1]]
                print back.first.tr("\r",'') if @show
              else
                regx = nil
              end
              unless regx.nil?
                case val
                when String, Fixnum, Float
                  send(val.to_s)
                when Array
                  back = chat(nil, *val) unless val.empty?
                  back = :redo if val.size <= 1
                when Proc
                  eval("proc {|m| $~ = m}", val.binding).call($~) if $~ # infuse proc with our match variables
                  back = back.is_a?(String) ? val.call(back) : val.call(*back) # don't convert embedded newlines to array
                  case val = back
                  when Array
                    if pure = (val.first == :pure)
                      line, @line = @line, ""
                      back = chat(nil, *val[1..-1]) unless val.size == 1
                      @line = line
                      back = :redo if val.size <= 2
                    else
                      back = chat(nil, *val) unless val.empty?
                      back = :redo if val.size <= 1
                    end
                  end
                when false, Symbol
                  if val == :this
                    back = back.first if back.is_a?(Array) # regexps store leading + matched text in back.first
                  else
                    back = val
                  end
                when true, nil
                  back = val
                when Hash
                  back = chat(val)
                else
                  raise "Hash literals can't multiplex to #{val.class} types"
                end
                break
              end
            else
              raise "Hash items can't process #{key}.class keys"
            end
          end and begin # read when nothing matches
            fast = read(item.has_key?(:else)) == :fast
            next
          end
          fast &&= false
          talk = false
          case back
            when :else then break
            when :redo then redo
            when :skip then return :skip
            when false, Symbol then return back
          end
          break
        when Array # walker
          if item.first == :pure
            ansi, @ansi = @ansi, :false
            line, @line = @line, ""
            back = talk ? chat(nil, *item[1..-1]) : chat(*item[1..-1])
            @ansi = ansi
            @line = line
          else
            back = talk ? chat(nil, *item) : chat(*item)
          end
          talk = false
          break
        when Proc, Method # macro
          item = item.to_proc if item.class == Method
          eval("proc {|m| $~ = m}", item.binding).call($~) if $~ # infuse proc with our match variables
          back = back.is_a?(String) ? item.call(back) : item.call(*back) # don't convert embedded newlines to array
          item = back unless back == :redo
          redo
        else # aborter
          raise "Chump doesn't handle #{item.class} objects like: #{item.inspect}"
        end
        read unless talk
      end
      case back
        when :redo  then break
        when :skip  then break
        when :false then return false # same as false in parent
        when :true  then return true  # same as true  in parent
        when :nil   then return nil   # same as nil   in parent
      end
    end
    back
  rescue Object => e
    exit if defined?(PTY::ChildExited) and e.class == PTY::ChildExited
    warn ['', '', "==[ #{e} ]=="       ] * "\n"
    warn ['', e.backtrace, ''].flatten   * "\n"
    warn ['', "Buffer: ", @buff.inspect] * "\n"
    warn ['', "Failed: ", item.inspect ] * "\n" if item
    disconnect
    exit
  end

  alias :wait :chat
  alias :[] :chat

  def read(fast=false)
    unless select([@io], nil, nil, fast ? @fast : @slow)
      return :fast if fast
      raise "Timeout" if @bomb
      return :slow
    end
    buff = @io.sysread(@size)
    buff.tr!("\r",'') if @nocr
    unless @ansi
      # http://www.esrl.noaa.gov/gmd/dv/hats/cats/stations/qnxman/Devansi.html
      # http://support.dell.com/support/edocs/systems/SC1425/en/ug/f3593ab0.htm
      buff.gsub!(/\x08/,'')
      buff.gsub!(/\e[=>]/,'')
      buff.gsub!(/\e\[(?>[^a-z]*)[a-z]/i,'')
    end
    print @nocr ? buff : buff.tr("\r",'') if @live
    @buff << buff
  end

  def unshift(str)
    Thread.exclusive { @buff = str + @buff }
  end

  def send(item='', *list)
    if back = item
      select(nil, [@io], nil, @slow) or return :slow
      if @wait
        prior = Time.now.to_f
        sleep(@wait[0] + rand * (@wait[1] - @wait[0]))
        @sleep += Time.now.to_f - prior
      end
      back = back.to_s
      @io.syswrite(back + @line) # line ending, usually "\r"
      print back.tr("\r",'') if @echo
    end
    back = chat(*list) unless list.empty?
    back
  end

  def peek(*list)
    list.compact.inject(:else=>false) {|h,v| h[v]=:this; h}
  end

  def disconnect
    @stop = Time.now
    print @buff.tr("\r",'') if @show
    @io.close
    puts
  end

end
