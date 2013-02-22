require 'ffi'
require 'socket'

module OxyFFI
  extend FFI::Library
  ffi_lib 'c'
  attach_function :socket, [:int, :int, :int], :int
  attach_function :getsockopt, [:int, :int, :int, :pointer, :pointer], :int
  attach_function :strerror, [:int], :string
end

s = OxyFFI.socket Socket::AF_INET, Socket::SOCK_STREAM, 0
if s < 0
  puts OxyFFI.strerror FFI::errno
  exit 1
end

version_ptr = FFI::MemoryPointer.new :int
length_ptr = FFI::MemoryPointer.new :int
length_ptr.write_int version_ptr.size

result = OxyFFI.getsockopt s, 0x4F585859, 0, version_ptr, length_ptr
if result == 0
  puts "Oxy version #{version_ptr.read_int} is looking at your sockets!"
else
  puts OxyFFI.strerror FFI::errno
end
