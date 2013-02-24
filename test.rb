require 'socket'

SOL_OXY = 0x4F585859 # oxy.h

s = Socket.new Socket::AF_INET, Socket::SOCK_STREAM

begin
  version_str = s.getsockopt SOL_OXY, 0
  puts "Oxy version #{version_str.unpack('S').first} is looking at your sockets!"
rescue Errno::EINVAL
  puts "Oxy not running."
end

