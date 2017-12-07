require 'json'
require 'socket'
require 'openssl'
require 'optparse'

options = {}
OptionParser.new do |opts|
  opts.on('-e', 'Environment') { |e| options[:env] = e }
  opts.on('-c', 'Cert name') { |c| options[:cert] = c }
  opts.on('-p', 'Cert password') { |p| options[:pass] = p }
  opts.on('-t', 'Device token') { |t| options[:token] = t }
end.parse!

hash_options = {}
options.keys.each_with_index { |o, i| hash_options[o] = ARGV[i] }

APNS_ERRORS = {
  1 => 'Processing error',
  2 => 'Missing device token',
  3 => 'Missing topic',
  4 => 'Missing payload',
  5 => 'Missing token size',
  6 => 'Missing topic size',
  7 => 'Missing payload size',
  8 => 'Invalid token',
  10 => 'APNs closed connection (possible maintenance)',
  255 => 'None (unknown error)'
}.freeze

SELECT_TIMEOUT = 5.freeze
ERROR_TUPLE_BYTES = 6.freeze

apns_port = 2195
apns_host = { 'dev' => 'gateway.sandbox.push.apple.com',
              'prod' => 'api.push.apple.com' }

apns_host   = apns_host[hash_options[:env]]
apns_cert   = hash_options[:cert]
cert_passwd = hash_options[:pass]
token       = hash_options[:token]

payload = { aps: { alert: "UTC Time: #{Time.now.utc} | :) hello test!",
                   badge: 1,
                   sound: 'default' } }.to_json
puts payload, "\n"

token = [token].pack('H*')

apns_message = (0.chr * 2) + 32.chr + token + 0.chr + payload.size.chr + payload

ssl_context = OpenSSL::SSL::SSLContext.new
p12 = OpenSSL::PKCS12.new(File.read(apns_cert), cert_passwd)
ssl_context.cert = p12.certificate
ssl_context.key  = p12.key
tcp_socket = TCPSocket.open(apns_host, apns_port)
ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
ssl_socket.sync = true

ssl_socket.connect
ssl_socket.write(apns_message)

puts 'Waitings server responce...'
unless IO.select([ssl_socket], nil, nil, SELECT_TIMEOUT)
  puts 'Success'
else
  data = ssl_socket.read(ERROR_TUPLE_BYTES)
  ssl_socket.flush
  ssl_socket.close
  _, code, notification_id = data.unpack('ccN') if data
  puts "Error: #{APNS_ERRORS[code]} on notification id #{notification_id}" if code && notification_id
end
