#!/usr/bin/ruby
# Copyright (c) 2016 Lorenzo Leonini
require 'colorize'
require 'json'
require 'net/http'
require 'ipaddress'
require 'trollop'

def exec(command)
	o = `#{command}`
	if $commands or $debug then puts command.black.on_white + "\n\n" end
	if $debug then puts o.light_blue end
	return o
end

def format_host(host, name)
	ip = public_ip(host)
	if !ip then return " #{host} domain not existing ? ".white.on_red end
	label = cdn_label(host)

	if host != name
		if ip != host
			o = " #{host}".black.on_light_white + " (#{ip}) ".light_black.on_light_white
		else
			o = " #{host} ".black.on_light_white
		end
	else
		o = " #{ip} ".black.on_white
	end
	o + label + "\n\n"
end

def format_domain(name)
	ip = public_ip(name)
	o = " #{name} ".light_white.on_blue
	if ip
		label = cdn_label(name, false)
		if label != '' then o += ' CDN: ' + label end
		
		cn = cname(name)
		
		if cn != ip and cn != name
			o += ' CNAME: ' + cn.yellow
		end
		
		o += " IP: #{ip.light_green}"
		
		ip_local = local_ip(name)
		if ip != ip_local
			o += " Local IP: #{ip_local.red}"
		end
		return o
	else
		return o + ' - ' + ' domain not existing ? '.white.on_red
	end
end

def analyze_domain(domain)
	name = domain['name']
	# Set a default host if none in config
	if !domain['hosts']
		if $host
			domain['hosts'] = [$host]
		else
			domain['hosts'] = [domain['name']]
		end
	end
	t_out = {}
	threads = []
	domain['hosts'].each do |host|
		threads << Thread.new {
			ip = public_ip(host)
			out = ''

			if ip
				out += indent(1, format_host(host, name))
				ssl = domain['ssl']
				if $ssl then ssl = true end
				if $nossl then ssl = false end

				url = 'http' + (if ssl then 's' else '' end) + '://' + name + (domain['path'] or '')
				out += indent(2, colorize_url(url))
				o = r_curl(name, ip, url)
				out += indent(3, pretty_curl(o))
				if o[0]['stats']['http_code'] == '200'
					content = domain['content']
					if $content then content = $content end
					if content
						out += indent(2, 'Content: ')
						if o[0]['content'] =~ /([^\n]{,25})#{content}([^\n]{,25})/
							out += indent(3, "...#{$1}".green + content.light_green + "#{$2}...".green )
						else
							out += indent(3, 'Not found: '.light_red + content.red)
						end
						out += "\n"
					end
				end

				last_uri = URI(o[0]['url'])
				if ssl or last_uri.scheme == 'https'
					out += indent(2, 'SSL: ')
					# SSL can be broken (detected by curl above) and then shown in green
					# here because a valid certificate is given (but not corresponding to
					# the domain)
					out += indent(3, ssl(ip, name)) + "\n"
				end
			else
				out += indent(1, " #{host} not found ".white.on_red + "\n")
			end
			t_out[host] = out
		}
	end
	threads.each { |thr| thr.join }
	out = format_domain(domain['name']) + "\n\n"
	domain['hosts'].each { |host| out += t_out[host] }
	return out
end

def cdn_label(host, background = true)
	cdn_name, cdn_comp = cdn(host)
	if cdn_name == 'AKAMAI'
		if cdn_comp == 'staging'
			if background
				return ' AKAMAI Staging '.black.on_cyan
			else
				return 'AKAMAI Staging'.light_cyan
			end
		else
			if background
				return ' AKAMAI Prod '.black.on_magenta
			else
				return 'AKAMAI Prod'.light_magenta
			end
		end
	elsif cdn_name
		if background
			return " #{cdn_name} ".black.on_blue
		else
			return cdn_name.light_blue
		end
	end
	''
end

def cdn(host)
	ak = akamai_host?(host)
	if ak then return ['AKAMAI', ak] end
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

def akamai_host?(host)
	o = dns(host)
	if o =~ /(edgesuite\.net)/ or o =~ /(edgekey\.net)/ or o =~ /(edgesuite-staging\.net)/ or o =~ /(edgekey-staging\.net)/
		if $1 =~ /staging/ then return 'staging' else return 'prod' end
	end
	false
end


def azure_ip?(ip)
	# TODO
	ip_in_list?(ip, list)
end

# https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html
# https://ip-ranges.amazonaws.com/ip-ranges.json
def cloudfront_ip?(ip)
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
def cloudflare_ip?(ip)
	list = <<-EOS
		103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 104.16.0.0/12
		108.162.192.0/18 131.0.72.0/22 141.101.64.0/18 162.158.0.0/15
		172.64.0.0/13 173.245.48.0/20 188.114.96.0/20 190.93.240.0/20
		197.234.240.0/22 198.41.128.0/17 199.27.128.0/21
	EOS
	ip_in_list?(ip, list)
end

# https://api.fastly.com/public-ip-list
def fastly_ip?(ip)
	list = <<-EOS
		23.235.32.0/20 43.249.72.0/22 103.244.50.0/24 103.245.222.0/23
		103.245.224.0/24 104.156.80.0/20 151.101.0.0/16 157.52.64.0/18
		172.111.64.0/18 185.31.16.0/22 199.27.72.0/21 199.232.0.0/16
		202.21.128.0/24 203.57.145.0/24
	EOS
	ip_in_list?(ip, list)
end

# https://www.maxcdn.com/one/assets/ips.txt
def maxcdn_ip?(ip)
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

def ip_in_list?(ip, list)
	ip = IPAddress ip
	list.lines.each do |l|
		l.split.each do |d|
			net = IPAddress d.strip
			if net.include?(ip) then return true end
		end
	end
	false
end

$local_hosts = nil
# Resolve first using /etc/hosts content
def local_ip(host)
	if !$local_hosts
		# parse and store /etc/hosts content via getent ahosts
		$local_hosts = {}
		o = exec('getent ahosts')
		o.lines.each do |line|
			if line =~ /([^\ ]*)[\ ]*(.*)/
				ip = $1
				hosts = $2
				hosts.split(' ').each do |h|
					$local_hosts[h] = ip
				end
			end
		end
	end
	if $local_hosts[host] then $local_hosts[host] else public_ip(host) end
end

$dns_cache = {}
def dns(host)
	if !$dns_cache[host] then $dns_cache[host] = exec("host #{host}") end
	$dns_cache[host]
end

def cname(host)
	o = dns(host)
	if o.lines.first =~ /is an alias for (.*)\./
		return $1
	end
	host
end

# Will NOT (by design) resolve with /etc/hosts
def public_ip(host)
	if IPAddress.valid?(host) then return host end
	o = dns(host)
	# Some providers, if domain is not found, send anyway an IP (that will then
	# redirect to their own custom error page...):
	# www.qafsfda.com has address 31.199.53.10
	# Host www.qafsfda.com not found: 3(NXDOMAIN)
	if o =~ /not found/ then return false end
	o.split("\n").each do |line|
		# XXX.in-addr.arpa has no PTR record
		# XXX.in-addr.arpa. not found: 3(NXDOMAIN)
		if line =~ /has address/ then return line.split()[3] end
	end
	false
end
def rev_ip(ip)
	if dns(ip) =~ /domain name pointer (.*)/ then $1.chop else nil end
end

# recursive curl
def r_curl(host, ip, url)
	# time_namelookup always = 0 because of resolve (and previous resolution)
	o = exec('curl -sSi -A "' + $agent + '" --compressed -H "Accept-encoding: gzip,deflate" ' +
		'-H "Pragma:akamai-x-cache-on,akamai-x-cache-remote-on,akamai-x-check-cacheable,' +
		'akamai-x-get-cache-key,akamai-x-get-extracted-values,akamai-x-get-nonces,' +
		'akamai-x-get-ssl-client-session-id,akamai-x-get-true-cache-key,akamai-x-serial-no" ' +
		'-w \'--STATS--\n' +
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

	m = parse_curl(url, o)
	if m['headers']['location']
		if m['headers']['location'] =~ URI::regexp
			loc = m['headers']['location']
		else
			uri = URI(url)
			loc = uri.scheme + '://' + uri.host + m['headers']['location']
		end
		r_curl(host, ip, loc).push(m)
	else
		[m]
	end
end

def parse_curl(url, s)
	o = {'url' => url}
	#if s =~ /http_code: 000/
		# ERROR
	#end
	o['title'] = s.lines.first.strip
	o['headers'] = {}
	s.lines.each do |l|
		l.strip!
		parts = l.split(': ')
		if parts.length > 1
			o['headers'][parts[0].downcase] = parts[1]
		elsif l == '' then break end
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
			if parts.length > 1
				o['stats'][parts[0]] = parts[1]
			end
		end
	end
	# Extract charset
	#if o['headers']['content-type']
		#options = o['headers']['content-type'].split(';')
		#options.each do |option|
			#option.strip!
			#if option =~ /charset=(.*)/
				#charset = $1
			#end
		#end
	#end
	# Trick to avoid further regex errors
	o['content'] = o['content'].encode('UTF-16be', :invalid => :replace, :replace => '?').encode('UTF-8')
	o
end

def colorize_url(url)
	uri = URI(url)
	o = ''
	if uri.scheme == 'https'
		o += uri.scheme.light_magenta
	elsif uri.scheme == 'http'
		o += uri.scheme.cyan
	end
	if uri.host
		o += '://'.cyan + uri.host.white
	end
	if uri.path
		o += uri.path.cyan
	end
	o
end

def pretty_curl(co)
	o = ''
	i = co.size - 1
	while i >= 0
		cur = co[i]
		if cur['title'] =~ /curl/
			return cur['title'].white.on_red + "\n\n"
		end
		if i > 0 or cur['stats']['http_code'] == '200'
			o += cur['title'].light_green + ' - ' + ((cur['stats']['time_total']).to_s + "s").yellow + "\n"
		else
			o += cur['title'].light_red + ' - ' + ((cur['stats']['time_total']).to_s + "s").yellow + "\n"
		end
		if $headers
			cur['headers'].sort.each do |col, v|
				if cur['headers'][col] and col != 'content'
					o += col.green + ': ' + v + "\n"
				end
			end
		else
			#['server', 'location'].each do |col|
				#if cur['headers'][col]
					#o += col.green + ': ' + cur['headers'][col] + "\n"
				#end
			#end
			if cur['headers']['server']
				o += 'server'.green + ': ' + cur['headers']['server'] + "\n"
			end
			if cur['headers']['location']
				o += 'location'.green + ': ' + colorize_url(cur['headers']['location']) + "\n"
			end
			if cur['stats']['http_code'] == '200'
				c = ''
				if cur['headers']['content-type']
					c += cur['headers']['content-type']
					if cur['headers']['content-length']
						c += ', length: ' + cur['headers']['content-length'].yellow
					else
						# Transfer-Encoding: chunked
						c += ', length: ' + cur['stats']['size_download'].yellow + ' (chunked)'
					end
					if cur['headers']['content-encoding']
						c += ', ' + cur['headers']['content-encoding'].green
					else
						c += ', ' + 'no compression'.red
					end
				end
				if c != ''
					o += 'content'.green + ': ' + c + "\n"
				end
			end
		end
		if $stats
			o += "Stats:\n".yellow
			cur['stats'].each do |col, v|
				o += col.green + ': ' + v + "\n"
			end
		end
		o += "\n"
		i -= 1
	end
	o
end

def tld(host)
	if IPAddress.valid?(host)
		return host
	else
		return host.match(/[^\.]*\.[a-zA-Z]{2,}$/)[0]
	end
end

def indent(level, s)
	if s == '' then return "\n" end
	l = 0
	i = ''
	while l < level
		i +=  '  '
		l += 1
	end
	o = ''
	s.lines.each { |l| o += i + l.strip.gsub("\n",'') + "\n" }
	o
end

def ssl(ip, domain)
	o = exec("openssl s_client -showcerts -servername #{domain} -connect #{ip}:443 2>&1 >/dev/null </dev/null")
	ok = true
	if o =~ /unable to/ or o =~ /verify error/ then ok = false end
	o.lines.each do |l|
		if l =~ /depth=0/
			if ok
				return l.gsub("\n", '').light_green
			else
				return l.gsub("\n", '').light_red
			end
		end
	end
	o.lines[0].gsub("\n", '').white.on_red
end

def find_config(data, d)
	data['domains'].each do |domain|
		if (!d or domain['name'] == d or domain['alias'] == d) and domain['hosts']
			return domain
		end
	end
	nil
end

$version = 'Check Domain (XD) 1.0 (c) 2016 Lorenzo Leonini'
$banner = <<-EOS
#{$version}

Usage:
		xd [options] <config|domain|url>*

where [options] are:

EOS
opts = Trollop::options do
  version $version
  banner $banner
  opt :list, 'List all domains in config (default)'
  opt :agent, 'Alternate user agent', :type => :string, :default => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.108 Safari/537.36'
  opt :all, 'Check all domains in config'
  opt :config, 'Alternate config file', :type => :string, :default => ENV['HOME'] + '/.domains.json'
  opt :content, 'Check specific content', :type => :string, :default => nil
  opt :host, 'Host/IP of the vhost (only if no config)', :type => :string, :default => nil
  opt :ssl, 'Force SSL'
  opt :nossl, 'Force without SSL'
  opt :headers, 'Show all headers'
  opt :stats, 'Show curl additional statistics'
  opt :commands, 'Show raw command'
  opt :debug, 'Show raw commands and outputs'
end

$list = opts[:list]
$agent = opts[:agent]
$all = opts[:all]
$config = opts[:config]
$content = opts[:content]
$host = opts[:host]
$ssl = opts[:ssl]
$nossl = opts[:nossl]
$headers = opts[:headers]
$stats = opts[:stats]
$commands = opts[:commands]
$debug = opts[:debug]
$urls = ARGV

begin
	$data = JSON.parse(File.read($config))
rescue
	puts "Config file not found: #{$config}"
	$data = {'domains' => []}
end

if !$urls then puts $version + "\n\nTry --help for help.\n\n" end
if $list or (!$all and $urls.size == 0)
	puts "Domains in current config (#{$config}):\n\n"
	$data['domains'].each do |domain|
		if domain['alias']
			puts "#{domain['alias'].light_blue} - #{domain['name'].light_green}:"
		else
			puts domain['name'].light_blue
		end
		if domain['hosts']
			domain['hosts'].each do |host|
				puts "\t#{host}"
			end
		end
	end
	puts
	exit
end

puts
$to_analyze = []
if $all then $to_analyze = $data['domains'] end
$urls.each do |url|
	config = find_config($data, url)
	if config
		puts "'#{url}' found in config file".green
		$to_analyze.push(config)
	else
		puts "'#{url}' not found in config file".yellow
		domain = { 'name' => url }
		if url =~ URI::regexp
			uri = URI(url)
			domain['name'] = uri.host
			domain['path'] = uri.path
			if uri.scheme == 'https'
				domain['ssl'] = true
			end
		end
		$to_analyze.push(domain)
	end
end

$public_ip = exec('GET http://ipecho.net/plain')
if IPAddress.valid?($public_ip)
	puts "\nChecks from ".blue + $public_ip.light_blue + ' - Agent: '.blue + $agent.light_blue + "\n\n"
else
	puts "\nCannot get public IP. Are you connected to internet ?".light_red + "\n\n"
end

$results = {}
$threads = []
$to_analyze.each do |domain|
	$threads << Thread.new { $results[domain] = analyze_domain(domain) }
end
$threads.each { |thr| thr.join }
$to_analyze.each do |domain|
	if $results[domain]
		puts $results[domain]
	end
end
