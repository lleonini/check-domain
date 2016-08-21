#!/usr/bin/ruby
# Copyright (c) 2016 Lorenzo Leonini
require 'bundler/setup'
require 'json'
require 'net/http'
require 'ipaddress'
require 'trollop'
require 'rainbow'
require 'filesize'
require 'htmlentities'

VERSION = '1.0'

module NewString
	refine String do
		# HTTP headers formatting
		def hd
			self.split('-').map(&:capitalize).join('-')
		end
		# style
		def s(name)
			light_green = '#33ff33'
			light_blue = '#0066ff'
			light_cyan = '#33ffff'
			light_magenta = '#ff33ff'
			light_red = '#ff0000'
			light_yellow = '#ffff66'
			white_blue = '#6699cc'
			white_cyan = '#66bbbb'
			white_magenta = '#bb66bb'
			
			host_background = '#333333'
			cdn = '#7777ff'
			case name
			when 'app'
				Rainbow(self).color(white_blue)
			when 'error'
				Rainbow(self).white.background(:red)
			when 'command'
				Rainbow(self).black.background(:white)
			when 'debug'
				Rainbow(self).color(light_blue)
			when 'domain.name'
				Rainbow(self).white.background(:blue)
			when 'domain.cname'
				Rainbow(self).color(:orange)
			when 'domain.ip'
				Rainbow(self).color(light_yellow)
			when 'domain.local_ip'
				Rainbow(self).color(light_red)
			when 'host.h'
				Rainbow(self).white.background(host_background)
			when 'host.ip'
				Rainbow(self).color('#888888').background(host_background)
			when 'cdn'
				Rainbow(self).color(cdn)
			when 'cdn.label'
				Rainbow(self).black.background(cdn)
			when 'cdn.akamai.staging'
				Rainbow(self).color(:blue)
			when 'cdn.akamai.staging.label'
				Rainbow(self).black.background(:blue)
			when 'cdn.akamai.prod'
				Rainbow(self).color(light_blue)
			when 'cdn.akamai.prod.label'
				Rainbow(self).black.background(light_blue)
			when 'url.http'
				Rainbow(self)
			when 'url.https'
				Rainbow(self).color('#66bb66')
			when 'url.host'
				Rainbow(self)
			when 'url.path'
				Rainbow(self).color('#66bbbb')
			when 'url.query'
				Rainbow(self).color('#66bb66')
			when 'curl.stats'
				Rainbow(self).color(:orange)
			when 'curl.http.ok'
				Rainbow(self).color(light_green)
			when 'curl.http.redirect'
				Rainbow(self).color(:orange)
			when 'curl.http.error'
				Rainbow(self).color(light_red)
			when 'curl.header'
				Rainbow(self).color('#00aa00')
			when 'curl.header.value'
				Rainbow(self).color('#cccccc')
			when 'curl.info'
				Rainbow(self).color('#ffff66')
			when 'curl.speed'
				Rainbow(self).color(white_blue)
			when 'curl.warn'
				Rainbow(self).color(light_red)
			when 'curl.ok'
				Rainbow(self).color(light_green)
			when 'akamai.ref'
				Rainbow(self).color(:red)
			when 'akamai.ref.value'
				Rainbow(self).color(light_red)
			when 'flag.ssl'
				Rainbow(self).color(:black).background(light_green)
			when 'flag.hsts'
				Rainbow(self).color(:black).background(:green)
			when 'content'
				Rainbow(self).green
			when 'content.found'
				Rainbow(self).color(light_green)
			when 'content.notfound'
				Rainbow(self).color(light_red)
			when 'ssl.ok'
				Rainbow(self).color(:green)
			when 'ssl.error'
				Rainbow(self).color(light_red)
			when 'config.alias'
				Rainbow(self).color(light_blue)
			when 'config.domain'
				Rainbow(self).color(light_green)
			when 'config.found'
				Rainbow(self).green
			when 'intro.value'
				Rainbow(self).color(white_blue)
			else
				self
			end
		end
		# block
		def b(name)
			(' ' + self + ' ').s(name)
		end
	end
end

module CheckDomain using NewString
	@@commands = false
	@@debug = false
	
	# https://stackoverflow.com/questions/10262235/printing-an-ascii-spinning-cursor-in-the-console
	def self.show_wait_spinner(fps = 10)
		chars = %w[| / - \\]
		delay = 1.0 / fps
		iter = 0
		spinner = Thread.new do
			while iter do  # Keep spinning until told otherwise
				print chars[(iter += 1) % chars.length]
				sleep delay
				print "\b"
			end
		end
		yield.tap do
			iter = false
			spinner.join
		end
	end

	def self.enc(s)
		if !s.valid_encoding?
			s = s.encode('UTF-16be', :invalid => :replace, :replace => '?').encode('UTF-8')
		end
		s
	end

	def self.exec(command)
		o = enc(`#{command}`)
		puts command.s('command') + "\n\n" if @@commands or @@debug
		puts o.s('debug') if @@debug
		o
	end

	def self.format_host(host, name)
		ip = public_ip(host)
		return "#{host} domain not existing ?".b('error') if !ip
		if host != name
			if ip != host
				o = "#{host} (#{ip})".b('host.h')
			else
				o = host.b('host.h')
			end
		else
			o = ip.b('host.h')
		end
		o + cdn_label(host) + "\n\n"
	end

	def self.format_domain(name)
		ip = public_ip(name)
		o = name.b('domain.name')
		if ip
			cn = cname(name)
			o += ' CNAME: ' + cn.s('domain.cname') if cn != ip and cn != name
			o += " IP: #{ip.s('domain.ip')}"
			ip_local = local_ip(name)
			o += " Local IP: #{ip_local.s('domain.local_ip')}" if ip != ip_local
			label = cdn_label(name, false)
			o += ' CDN: ' + label if label != ''
			return o
		else
			return o + ' - ' + 'domain not existing ?'.b('error')
		end
	end

	def self.sanitize_domain(domain, options)
		# Set a default host if none in config
		if !domain['hosts']
			if options['host']
				domain['hosts'] = [options['host']]
			else
				domain['hosts'] = [domain['name']]
			end
		end
		domain
	end
		
	def self.analyze_domain(domain, options)
		domain = sanitize_domain(domain, options)
		name = domain['name']
		t_out = {}
		threads = []
		domain['hosts'].each do |host|
			threads << Thread.new {
				ip = public_ip(host)
				out = ''

				if ip
					out += indent(1, format_host(host, name))
					ssl = domain['ssl']
					ssl = true if options['ssl']
					ssl = false if options['nossl']
					url = 'http' + (ssl ? 's' : '') + '://' + name + (domain['path'] or '')
					curl_options = options.clone
					curl_options['user'] ||= domain['user']
					o = r_curl(name, ip, url, curl_options)
					out += indent(2, format_curl(o, options))
					if o[0].key?('stats') and o[0]['stats']['http_code'] == '200'
						content = domain['content']
						content = options['content'] if options['content']
						if content
							if o[0]['content'] =~ /([^\n\r]{,25})#{content}([^\n\r]{,25})/
								out += indent(2, 'Content: ' + "...#{$1}".s('content') + content.s('content.found') + "#{$2}...".s('content'))
							else
								out += indent(2, 'Content: ' + ('Not found: ' + content).s('content.notfound'))
							end
							out += "\n"
						end
					end

					last_uri = URI(o[0]['url'])
					if ssl or last_uri.scheme == 'https'
						# SSL can be broken (detected by curl above) and then shown in green
						# here because a valid certificate is given (but not corresponding to
						# the domain)
						out += indent(2, 'SSL: ' + ssl(ip, last_uri.host)) + "\n"
					end
				else
					out += indent(1, "#{host} not found".b('error') + "\n\n")
				end
				t_out[host] = out
			}
		end
		threads.each { |thr| thr.join }
		out = format_domain(domain['name']) + "\n\n"
		domain['hosts'].each { |host| out += t_out[host] }
		out
	end

	def self.cdn_label(host, background = true)
		cdn_name, cdn_comp = cdn(host)
		if cdn_name == 'AKAMAI'
			if cdn_comp == 'staging'
				if background
					return 'AKAMAI Staging'.b('cdn.akamai.staging.label')
				else
					return 'AKAMAI Staging'.s('cdn.akamai.staging')
				end
			else
				if background
					return 'AKAMAI Prod'.b('cdn.akamai.prod.label')
				else
					return 'AKAMAI Prod'.s('cdn.akamai.prod')
				end
			end
		elsif cdn_name
			if background
				return cdn_name.b('cdn.label')
			else
				return cdn_name.s('cdn')
			end
		end
		''
	end

	def self.cdn(host)
		ak = akamai_host?(host)
		return ['AKAMAI', ak] if ak
		ip = public_ip(host)
		if cloudflare_ip?(ip)
			return ['CloudFlare']
		elsif cloudfront_ip?(ip)
			return ['CloudFront']
		elsif maxcdn_ip?(ip)
			return ['MaxCDN']
		elsif fastly_ip?(ip)
			return ['Fastly']
		end
		nil
	end

	def self.akamai_host?(host)
		o = dns(host)
		if o =~ /(edgesuite\.net)/ or o =~ /(edgekey\.net)/ or o =~ /(edgesuite-staging\.net)/ or o =~ /(edgekey-staging\.net)/
			if $1 =~ /staging/ then return 'staging' else return 'prod' end
		end
		false
	end

	def self.azure_ip?(ip)
		# TODO
		ip_in_list?(ip, list)
	end

	# https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html
	# https://ip-ranges.amazonaws.com/ip-ranges.json
	def self.cloudfront_ip?(ip)
		list = <<-EOS
			52.84.0.0/15 54.182.0.0/16 54.192.0.0/16 54.230.0.0/16
			54.239.128.0/18 54.239.192.0/19 54.240.128.0/18 204.246.164.0/22
			204.246.168.0/22 204.246.174.0/23 204.246.176.0/20 205.251.192.0/19
			205.251.249.0/24 205.251.250.0/23 205.251.252.0/23 205.251.254.0/24
			216.137.32.0/19
		EOS
		ip_in_list?(ip, list)
	end

	# https://www.cloudflare.com/ips-v4
	def self.cloudflare_ip?(ip)
		list = <<-EOS
			103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 104.16.0.0/12
			108.162.192.0/18 131.0.72.0/22 141.101.64.0/18 162.158.0.0/15
			172.64.0.0/13 173.245.48.0/20 188.114.96.0/20 190.93.240.0/20
			197.234.240.0/22 198.41.128.0/17 199.27.128.0/21
		EOS
		ip_in_list?(ip, list)
	end

	# https://api.fastly.com/public-ip-list
	def self.fastly_ip?(ip)
		list = <<-EOS
			23.235.32.0/20 43.249.72.0/22 103.244.50.0/24 103.245.222.0/23
			103.245.224.0/24 104.156.80.0/20 151.101.0.0/16 157.52.64.0/18
			172.111.64.0/18 185.31.16.0/22 199.27.72.0/21 199.232.0.0/16
			202.21.128.0/24 203.57.145.0/24
		EOS
		ip_in_list?(ip, list)
	end

	# https://www.maxcdn.com/one/assets/ips.txt
	def self.maxcdn_ip?(ip)
		list = <<-EOS
			108.161.176.0/20 94.46.144.0/20 146.88.128.0/20 198.232.124.0/22
			23.111.8.0/22 217.22.28.0/22 64.125.76.64/27 64.125.76.96/27
			64.125.78.96/27 64.125.78.192/27 64.125.78.224/27 64.125.102.32/27
			64.125.102.64/27 64.125.102.96/27 94.31.27.64/27 94.31.33.128/27
			94.31.33.160/27 94.31.33.192/27 94.31.56.160/27 177.54.148.0/24
			185.18.207.64/26 50.31.249.224/27 50.31.251.32/28 119.81.42.192/27
			119.81.104.96/28 119.81.67.8/29 119.81.0.104/30 119.81.1.144/30
			27.50.77.226/32 27.50.79.130/32 119.81.131.130/32 119.81.131.131/32
			216.12.211.59/32 216.12.211.60/32 37.58.110.67/32 37.58.110.68/32
			158.85.206.228/32 158.85.206.231/32 174.36.204.195/32 174.36.204.196/32
			151.139.0.0/19 94.46.144.0/21 103.66.28.0/22 103.228.104.0/22
		EOS
		ip_in_list?(ip, list)
	end

	def self.ip_in_list?(ip, list)
		ip = IPAddress ip
		list.lines.each do |l|
			l.split.each do |d|
				net = IPAddress d.strip
				return true if net.include?(ip)
			end
		end
		false
	end

	@@local_hosts = nil
	# Resolve first using /etc/hosts content
	def self.local_ip(host)
		if !@@local_hosts
			# parse and store /etc/hosts content via getent ahosts
			@@local_hosts = {}
			o = exec('getent ahosts')
			o.lines.each do |line|
				if line =~ /([^\ ]*)[\ ]*(.*)/
					ip = $1
					hosts = $2
					hosts.split(' ').each do |h|
						@@local_hosts[h] = ip
					end
				end
			end
		end
		if @@local_hosts[host] then @@local_hosts[host] else public_ip(host) end
	end

	@@dns_cache = {}
	def self.dns(host)
		@@dns_cache[host] = exec("host #{host}") if !@@dns_cache[host]
		@@dns_cache[host]
	end

	def self.cname(host)
		if dns(host).lines.first =~ /is an alias for (.*)\./ then $1 else host end
	end

	def self.my_ip
		ip = exec('curl -s http://ipecho.net/plain 2>&1')
		if IPAddress.valid?(ip) then ip else nil end
	end
	
	# Will NOT resolve using /etc/hosts
	def self.public_ip(host)
		return host if IPAddress.valid?(host)
		o = dns(host)
		# Some providers, if domain is not found, send anyway an IP (that will then
		# redirect to their own custom error page...):
		# www.qafsfda.com has address 31.199.53.10
		# Host www.qafsfda.com not found: 3(NXDOMAIN)
		return false if o =~ /not found/
		o.split("\n").each do |line|
			# XXX.in-addr.arpa has no PTR record
			# XXX.in-addr.arpa. not found: 3(NXDOMAIN)
			return line.split()[3] if line =~ /has address/
		end
		false
	end
	def self.rev_ip(ip)
		if dns(ip) =~ /domain name pointer (.*)/ then $1.chop else nil end
	end

	# Recursive curl
	def self.r_curl(host, ip, url, options)
		cookies = ''
		if options['cookies']
			options['cookies'].each do |cookie|
				cookies += " --cookie '#{cookie}'"
			end
		end
		headers = ' --header "Accept-encoding: gzip,deflate"'
		if options['headers']
			options['headers'].each do |header|
				headers += " --header '#{header}'"
			end
		end
		akamai_headers = 
			' --header "Pragma:akamai-x-get-client-ip,akamai-x-feo-trace,akamai-x-get-request-id,' +
			'akamai-x-request-trace,akamai-x--meta-trace,akama-xi-get-extracted-values,' +
			'akamai-x-cache-on,akamai-x-cache-remote-on,akamai-x-check-cacheable,' +
			'akamai-x-get-cache-key,akamai-x-get-extracted-values,akamai-x-get-nonces,' +
			'akamai-x-get-ssl-client-session-id,akamai-x-get-true-cache-key,akamai-x-serial-no"'
		user = options['user'] ? " --user \"#{options['user']}\" " : ''
		agent = options['agent'] ? " --user-agent \"#{options['agent']}\" " : ''
		max_time = ' --connect-timeout ' + options['max-time'].to_s + ' -m ' + (options['max-time'] + 10).to_s

		o = exec('curl -sSi --compressed' + cookies + headers +
			user + agent + max_time + akamai_headers +
			' -w \'\n--STATS--\n' +
			'http_code: %{http_code}\n' +
			'size_download: %{size_download}\n' +
			'speed_download: %{speed_download}\n' +
			'time_namelookup: %{time_namelookup}\n' +
			'time_connect: %{time_connect}\n' +
			'time_appconnect: %{time_appconnect}\n' +
			'time_redirect: %{time_redirect}\n' +
			'time_pretransfer: %{time_pretransfer}\n' +
			'time_starttransfer: %{time_starttransfer}\n' +
			'time_total: %{time_total}\n\' ' +
			"--resolve #{host}:80:#{ip} --resolve #{host}:443:#{ip} '#{url}' 2>&1")

		# major error
		# curl: (60) server certificate verification failed. CAfile: /etc/ssl/certs/ca-certificates.crt CRLfile: none
		if o.lines.first =~ /^curl: \(/
			[{'url' => url, 'error' => o.lines.first.chop}]
		else
			m = parse_curl(url, o)
			if m['headers']['location']
				if m['headers']['location'] =~ URI::regexp
					loc = m['headers']['location']
				else
					uri = URI(url)
					loc = uri.scheme + '://' + uri.host + m['headers']['location']
				end
				return r_curl(host, ip, loc, options).push(m)
			else
				return [m]
			end
		end
	end

	def self.parse_curl(url, s)
		o = {'url' => url}
		o['title'] = s.lines.first.strip
		headers = {}
		s.lines.each do |l|
			l.strip!
			parts = l.split(': ')
			if parts.length > 1
				n = parts[0].downcase
				headers[n] = {} if !headers.key?(n)
				headers[n][parts[1]] = true
			elsif l == '' then break end
		end
		o['headers'] = {}
		headers.each do |k, vs|
			o['headers'][k] = vs.keys.join(' | ')
		end
		show = false
		o['content'] = ''
		o['stats'] = {}
		s.lines.each do |l|
			if show == false
				if l.include? '--STATS--'
					show = true
				elsif
					o['content'] += l
				end
			elsif
				parts = l.strip.split(': ')
				o['stats'][parts[0]] = parts[1] if parts.length > 1
			end
		end
		o
	end

	def self.format_url(url)
		uri = URI(url)
		o = ''
		if uri.scheme == 'https'
			o += uri.scheme.s('url.https')
		elsif uri.scheme == 'http'
			o += uri.scheme.s('url.http')
		end
		o += '://'.s('url.path') + uri.host.s('url.host') if uri.host
		o += uri.path.s('url.path') if uri.path
		if uri.query
			query = (uri.query.length < 40 ? uri.query : uri.query[0, 38] + '...') 
			o += ('?' + query).s('url.query')
		end
		o
	end

	def self.format_curl(co, options)
		o = ''
		i = co.size - 1
		while i >= 0
			cur = co[i]
			uri = URI(cur['url'])
			o += format_url(cur['url'])
			if !cur.key?('error')
				o += (' - ' + cur['stats']['time_total'].to_f.round(2).to_s + "s").s('curl.info')
				o += (' ' + Filesize.from(cur['stats']['speed_download'] + ' B').pretty + '/s').s('curl.speed') if cur['stats']['http_code'].to_i == 200
				o += ' ' + 'SSL'.b('flag.ssl') if uri.scheme == 'https'
				o += ' ' + 'HSTS'.b('flag.hsts') if cur['headers']['strict-transport-security']
			end
			o += "\n"
			o += indent(1, _format_curl(cur, options))
			#o += "\n"
			i -= 1
		end
		o += "\n"
		o
	end

	def self._format_curl(cur, options)
		o = ''
		return o + cur['error'].s('error') + "\n" if cur.key?('error')
		
		http_code = cur['stats']['http_code'].to_i
		if http_code >= 200 and http_code < 300
			o += cur['title'].s('curl.http.ok')
		elsif http_code >= 300 and http_code < 400
			o += cur['title'].s('curl.http.redirect')
		else
			o += cur['title'].s('curl.http.error')
		end
		o += "\n"
		
		if options['show_headers']
			cur['headers'].sort.each do |col, v|
				if cur['headers'][col] and col != 'content'
					o += col.hd.s('curl.header') + ': ' + v.s('curl.header.value') + "\n"
				end
			end
		else
			if cur['headers']['server']
				o += 'Server'.s('curl.header') + ': ' + cur['headers']['server'].s('curl.header.value')
				o += ' (' + cur['headers']['via'] + ')' if cur['headers']['via']
				o += "\n"
			end
			if cur['stats']['http_code'] == '200'
				c = ''
				if cur['headers']['content-type']
					c += cur['headers']['content-type']
					if cur['headers']['content-length']
						c += ', ' + Filesize.from(cur['headers']['content-length'] + ' B').pretty.s('curl.info')
					else # Transfer-Encoding: chunked
						c += ', ' + Filesize.from(cur['stats']['size_download'] + ' B').pretty.s('curl.info') + ' (chunked)'
					end
					if cur['headers']['content-encoding']
						c += ', ' + cur['headers']['content-encoding'].s('curl.ok')
					else
						c += ', ' + 'no compression'.s('curl.warn')
					end
				end
				o += 'Content'.s('curl.header') + ': ' + c.s('curl.header.value') + "\n" if c != ''
			end
		end
		if options['show_stats']
			o += "Stats:\n".s('curl.stats')
			cur['stats'].each do |col, v|
				o += col.s('curl.header') + ': ' + v.s('curl.header.value') + "\n"
			end
		end
		# Akamai error
		# Reference&#32;&#35;9&#46;876ddead&#46;1471509839&#46;12baa122
		if cur['headers']['server'] == 'AkamaiGHost' and cur['content'] =~ /^Reference&#32;&#35;(.*)$/
			o += 'Akamai reference'.s('akamai.ref') + ': ' + HTMLEntities.new.decode($1).s('akamai.ref.value') + "\n"
		end
		o
	end

	def self.indent(level, s)
		return "\n" if s == ''
		l = 0
		i = ''
		while l < level
			l += 1
			i +=  '   '
		end
		o = ''
		s.lines.each { |l| o += i + l.rstrip.gsub("\n",'') + "\n" }
		o
	end

	def self.ssl(ip, domain)
		o = exec("openssl s_client -showcerts -servername #{domain} -connect #{ip}:443 2>&1 >/dev/null </dev/null")
		ok = if o =~ /unable to/ or o =~ /verify error/ then false else true end
		o.lines.each do |l|
			if l =~ /depth=0/
				if ok
					return l.gsub("\n", '').s('ssl.ok')
				else
					return l.gsub("\n", '').s('ssl.error')
				end
			end
		end
		o.lines[0].gsub("\n", '').b('error')
	end

	def self.find_config(data, d)
		data['domains'].each do |domain|
			return domain if domain['name'] == d
			domain['alias'].split.each do |a|
				return domain if a == d
			end if domain['alias']
		end
		nil
	end

	def self.list_domains(data)
		o = ''
		data['domains'].each do |domain|
			if domain['alias']
				o += "#{domain['alias'].s('config.alias')} - #{domain['name'].s('config.domain')}\n"
			else
				o += domain['name'].s('config.alias') + "\n"
			end
			if domain['hosts']
				i = ''
				domain['hosts'].each do |host|
					i += "#{host}\n"
				end
				o += indent(1, i)
			end
		end
		o
	end

	def self.analyze(domains, options)
		results = {}
		threads = []
		i = 0
		domains.each do |domain|
			threads << Thread.new(i) {|i| results[i] = analyze_domain(domain, options) }
			i += 1
		end

		if !@@commands and !@@debug
			print 'Checking...'
			show_wait_spinner { threads.each { |thr| thr.join } }
			print "\r              \r"
		else
			threads.each { |thr| thr.join }
		end

		o = ''
		i = 0
		domains.each do |domain|
			o += results[i]
			i += 1
		end
		o
	end

	def self.find_to_analyze(data, urls, all)
		o = ''
		to_analyze = []
		to_analyze = data['domains'] if all
		urls.each do |url|
			config = find_config(data, url)
			if config
				o += "'#{url}' found in config file\n".s('config.found')
				to_analyze.push(config)
			else
				domain = { 'name' => url }
				if url =~ URI::regexp
					uri = URI(url)
					domain['name'] = uri.host
					domain['path'] = uri.path
					domain['path'] += '?' + uri.query if uri.query
					domain['user'] = uri.user + ':' + uri.password if uri.user and uri.password
					domain['ssl'] = true if uri.scheme == 'https'
				end
				to_analyze.push(domain)
			end
		end
		return to_analyze, o
	end

	def self.command_line
		o_argv = ARGV.clone
		version = "Check Domain (XD) #{VERSION} (c) 2016 Lorenzo Leonini".s('app')
		banner = <<-EOS
#{version}

Usage:
		xd [options] <url|domain|config>*

Where [options] are:

		EOS
		opts = Trollop::options do
			version version
			banner banner
			# -h help
			opt :list, 'List all domains in config', :short => '-l'
			opt :user, '<user:password>: HTTP Basic Authentication', :short => '-u', :type => :string
			opt 'user-agent', '<agent>: alternate user agent', :short => '-A', :type => :string
			opt :all, 'Check all domains in config', :short => '-a'
			opt :content, '<content>: check if content exists', :short => '-c', :type => :string
			opt :host, '<host>: host/IP of the vhost (only if no config)', :short => '-o', :type => :string
			opt :ssl, 'Force all checks with SSL', :short => '-s'
			opt :nossl, 'Force all checks without SSL', :short => '-n'
			opt :headers, 'Show all headers', :short => '-i'
			opt :stats, 'Show curl additional statistics', :short => '-t'
			opt :commands, 'Show raw commands', :short => '-v'
			opt :debug, 'Show raw commands and their outputs', :short => '-d'
			opt :colors, 'Force colors output'
			opt :nocolors, 'Remove colors'
			opt :config, '<file>: alternate config file', :short => '-f', :type => :string, :default => ENV['HOME'] + '/.xd.json'
			opt 'max-time', '<value>: curl timeout', :short => '-m', :type => :int, :default => 30
			opt :cookie, '<name=data>: set cookie', :short => '-b', :type => :string, :multi => true
			opt :header, '<header>: set header', :short => '-H', :type => :string, :multi => true
		end

		list = opts[:list]
		agent = opts['user-agent']
		agent ||= "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
		all = opts[:all]
		config_file = opts[:config]
		@@commands = opts[:commands]
		@@debug = opts[:debug]
		if opts[:colors] then Rainbow.enabled = true end
		if opts[:nocolors] then Rainbow.enabled = false end
		urls = ARGV

		options = {
			'user' => opts[:user],
			'agent' => agent,
			'content' => opts[:content],
			'cookies' => opts[:cookie],
			'headers' => opts[:header],
			'host' => opts[:host],
			'ssl' => opts[:ssl],
			'nossl' => opts[:nossl],
			'show_headers' => opts[:headers],
			'show_stats' => opts[:stats],
			'max-time' => opts['max-time'],
		}
		
		# Can only be called after Trollop::options
		# If o_argv.empty?, this will exit
		Trollop::educate if o_argv.empty?
		
		return list, all, config_file, urls, options
	end

	def self.run
		list, all, config_file, urls, options = command_line

		data = {'domains' => []}
		if File.exists?(config_file)
			begin
				data = JSON.parse(File.read(config_file))
			rescue
				puts "Broken config file: #{config_file}"
				exit
			end
		end

		if list
			o = "Domains in config (#{config_file}):\n\n"
			o += list_domains(data)
			puts o
			exit
		end
		
		ip = my_ip
		if ip
			puts "\nChecks from ".s('intro') + ip.s('intro.value') + ' ' +
				'Agent: '.s('intro') + "#{options['agent']} ".s('intro.value') + "\n\n"
		else
			puts "\n" + 'Cannot get public IP. Are you connected to internet ?'.b('error') + "\n\n"
			exit
		end

		to_analyze, o  = find_to_analyze(data, urls, all)

		puts o if o.length > 0
		puts analyze(to_analyze, options)
	end
end

CheckDomain.run
