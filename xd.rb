#!/usr/bin/ruby
# Copyright (c) 2016 Lorenzo Leonini
require 'colorize'
require 'uri'
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

def show_host(host)
	ak = akamaiHost(host)
	if ak
		if ak == "staging"
			#return "<AKAMAI Staging: #{host}>".cyan
			return " AKAMAI Staging ".black.on_cyan
		else
			#return "<AKAMAI Prod: #{host}>".light_magenta
			return " AKAMAI Prod ".black.on_magenta
		end
	end
	ip = publicIP host
	if cloudflareIP?(ip)
		return " CloudFlare: #{ip} ".black.on_blue
	elsif host == ip
		return " #{host} ".black.on_yellow
	else
		if ip
			return " #{host} - #{ip} ".black.on_yellow
		else
			return " #{host} domain not existing ? ".white.on_red
		end
	end
end

def show_domain(name)
	ip = publicIP name
	o = " #{name} ".light_white.on_blue
	if ip
		cn = cname name
		ak = akamaiHost cn
		if ak == "staging"
			o += " - CNAME " + ("AKAMAI Staging: " + cn).cyan
		elsif ak == "prod"
			o += " - CNAME " + ("AKAMAI Prod: " + cn).light_magenta
		elsif cloudflareIP? ip
			o += " - " + "CloudFlare".light_blue
		elsif cn != ip and cn != name
			o += " - CNAME: " + cn.light_yellow
		end
		
		o += " - Public IP: #{ip.light_green}"
		ip_local = localIP name
		if ip != ip_local and etchosts() =~ /#{name}/
			o += " - Local IP: #{ip_local.white.on_red}"
		end
		return o
	else
		return o + " - " + " domain not existing ? ".white.on_red
	end
end

def analyze_domain(domain)
	t_out = {}
	threads = []
	if !domain.key?('hosts')
		if $host
			domain["hosts"] = [$host]
		else
			domain["hosts"] = [domain["name"]]
		end
	end
	domain['hosts'].each do |host|
		threads << Thread.new {
			name = domain['name']
			out = ''

			ip = publicIP host
			if ip
				out += indent(1, show_host(host))
				ssl = domain['ssl']
				if $ssl then ssl = true end
				if $nossl then ssl = false end

				url = 'http' + (if ssl then "s" else "" end) + '://' + name + (domain['path'] or "")
				out += indent 2, url
				o = rCurl name, ip, url
				out += indent 3, prettyCurl(o)
				if o[0]['stats']['http_code'] == '200'
					if $content then content = $content end
					if content
						out += indent 2, "Content: "
						if o[0]['content'] =~ /([^^]{,25})#{content}([^$]{,25})/
							out += indent 3, "...#{$1}".green + content.light_green + "#{$2}...".green 
						else
							out += indent 3, "ERROR: ".light_red + content 
						end
						out += "\n"
					end
				end

				if ssl
					out += indent 2, "SSL: "
					# SSL can be broken (detected by curl above) and then shown in green
					# here because a valid certificate is given (but not corresponding to
					# the domain)
					out += indent 3, ssl(ip, name)
				end
			else
				out += indent 1, " #{host} not found ".white.on_red + "\n"
			end
			t_out[host] = out + "\n"
		}
	end
	threads.each { |thr| thr.join }
	out = show_domain(domain['name']) + "\n\n"
	domain['hosts'].each { |host| out += t_out[host] }
	return out
end

def akamaiHost(host)
	if host =~ /edgesuite/ or host =~ /edgekey/
		if host =~ /staging/ then return "staging" else return "prod" end
	end
	false
end

# https://www.cloudflare.com/ips-v4
def cloudflareIP?(ip)
	ip = IPAddress ip
	list = <<-EOS
		103.21.244.0/22
		103.22.200.0/22
		103.31.4.0/22
		104.16.0.0/12
		108.162.192.0/18
		131.0.72.0/22
		141.101.64.0/18
		162.158.0.0/15
		172.64.0.0/13
		173.245.48.0/20
		188.114.96.0/20
		190.93.240.0/20
		197.234.240.0/22
		198.41.128.0/17
		199.27.128.0/21
	EOS
	list.lines.each do |l|
		net = IPAddress l.strip
		if net.include? ip then return true end
	end
	false
end

# TODO localIP() and etchosts() could be merged in a function that return all
# local domains => local ip and then use that array
def etchosts()
	return exec "getent ahosts"
end
def localIP(host)
	o = exec "getent ahosts #{host}"
	if o.length > 1
		return o.lines[0].split(' ')[0]
	else
		return false
	end
end

$cname_cache = {}
def cname(host)
	if !$cname_cache.key?(host) then $cname_cache[host] = _cname(host) end
	return $cname_cache[host]
end
# Try to find the first CNAME not in the same domain (if possible)
def _cname(host)
	o = exec "host #{host}"
	if o.lines.first =~ /is an alias for (.*)\./
		cn = $1
		if tld(host) == tld(cn) 
			return _cname cn
		else
			return cn
		end
	end
	host
end

# Will NOT (by design) resolve with /etc/hosts
$public_ip_cache = {}
def publicIP(host)
	if IPAddress.valid? host then return host end
	if ! $public_ip_cache.key?(host) then $public_ip_cache[host] = _publicIP host end
	$public_ip_cache[host]
end
def _publicIP(host)
	dns = exec "host #{host}"
	# Some providers, if domain is not found, send anyway an IP (that will then
	# redirect to their own custom error page...):
	# www.qafsfda.com has address 31.199.53.10
	# Host www.qafsfda.com not found: 3(NXDOMAIN)
	if dns =~ /not found/ then return false end
	dns.split("\n").each do |line|
		# XXX.in-addr.arpa has no PTR record
		# XXX.in-addr.arpa. not found: 3(NXDOMAIN)
		if line =~ /has address/ then return line.split()[3] end
	end
	false
end

def rCurl(host, ip, url)
	# time_namelookup always 0 because of resolve (and previous resolution)
	o = exec 'curl -sSi -A "' + $agent + '" --compressed -H "Accept-encoding: gzip,deflate" ' +
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
		"--resolve #{host}:80:#{ip} --resolve #{host}:443:#{ip} '#{url}' 2>&1"

	m = curlMap(url, o)
	if m['headers'].key? 'Location'
		if m['headers']['Location'] =~ URI::regexp
			loc = m['headers']['Location']
		else
			uri = URI(url)
			loc = uri.scheme + "://" + uri.host + m['headers']['Location']
		end
		rCurl(host, ip, loc).push(m)
	else
		[m]
	end
end

def curlMap(url, s)
	o = {'url' => url}
	#if s =~ /http_code: 000/
		#puts "ERROR"
	#end
	o['title'] = s.lines.first.strip
	o['headers'] = {}
	s.lines.each do |l|
		l.strip!
		parts = l.split(': ')
		if parts.length > 1
			o['headers'][parts[0]] = parts[1]
		elsif l == '' then break end
	end
	show = false
	o['content'] = ''
	o['stats'] = {}
	s.lines.each do |l|
		l.strip!
		if show == false
			if l.include? '--STATS--'
				show = true
			elsif
				o['content'] += l
			end
		elsif
			parts = l.split(': ')
			if parts.length > 1
				o['stats'][parts[0]] = parts[1]
			end
		end
	end
	# Extract charset
	#if o['headers'].key?('Content-Type')
		#options = o['headers']['Content-Type'].split(';')
		#options.each do |option|
			#option.strip!
			#if option =~ /charset=(.*)/
				#charset = $1
			#end
		#end
	#end
	# Trick to avoid further regex errors
	o['content'] = o['content'].encode("UTF-16be", :invalid => :replace, :replace => '?').encode('UTF-8')
	o
end

def prettyCurl(co)
	o = ''
	i = co.size - 1
	while i >= 0
		cur = co[i]
		if cur['title'] =~ /curl/
			return cur['title'].white.on_red + "\n\n"
		end
		if i > 0 or cur['stats']['http_code'] == '200'
			o += cur['title'].light_green + " - " + ((cur['stats']['time_total']).to_s + "s").yellow + "\n"
		else
			o += cur['title'].light_red + " - " + ((cur['stats']['time_total']).to_s + "s").yellow + "\n"
		end
		if $headers
			cur['headers'].sort.each do |col, v|
				if cur['headers'].key?(col) and col != "content"
					o += col.green + ": " + v + "\n"
				end
			end
		else
			['Server', 'Location'].each do |col|
				if cur['headers'].key?(col)
					o += col.green + ": " + cur['headers'][col] + "\n"
				end
			end
			if cur['stats']['http_code'] == '200'
				c = ''
				if cur['headers'].key?('Content-Type')
					c += cur['headers']['Content-Type']
					if cur['headers'].key?('Content-Length')
						c += ", length: " + cur['headers']['Content-Length'].yellow
					else
						# Transfer-Encoding: chunked
						c += ", length: " + cur['stats']['size_download'].yellow + " (chunked)"
					end
					if cur['headers'].key?('Content-Encoding')
						c += ", " + cur['headers']['Content-Encoding'].green
					else
						c += ", " + "no compression".red
					end
				end
				if c != ''
					o += 'Content'.green + ": " + c + "\n"
				end
			end
		end
		if $stats
			o += "Stats:\n".yellow
			cur['stats'].each do |col, v|
				o += col.green + ": " + v + "\n"
			end
		end
		o += "\n"
		i -= 1
	end
	o
end

def tld(host)
	if IPAddress.valid? host
		return host
	else
		return host.match(/[^\.]*\.[a-zA-Z]{2,}$/)[0]
	end
end

def indent(level, s)
	if s == '' then return "\n" end
	l = 0
	i = ""
	while l < level
		i +=  "  "
		l += 1
	end
	o = ""
	s.lines.each { |l| o += i + l.strip.gsub("\n",'') + "\n" }
	o
end

def ssl(ip, domain)
	o = exec "openssl s_client -showcerts -servername #{domain} -connect #{ip}:443 2>&1 >/dev/null </dev/null"
	ok = true
	if o =~ /unable to/ or o=~ /verify error/ then ok = false end
	o.lines.each do |l|
		if l =~ /depth=0/
			if ok
				return l.gsub("\n",'').light_green
			else
				return l.gsub("\n",'').light_red
			end
		end
	end
	o.lines[0].gsub("\n",'').white.on_red
end

def findConfig(data, d)
	data['domains'].each do |domain|
		if (!d or domain['name'] == d or domain['alias'] == d) and domain['hosts']
			return domain
		end
	end
	false
end

$version = "Check Domain (XD) 1.0 (c) 2016 Lorenzo Leonini"
$banner = <<-EOS
#{$version}

Usage:
		xd [options] <config|domain|url>*

where [options] are:

EOS
opts = Trollop::options do
  version $version
  banner $banner
  opt :list, "List all domains in config (default)"
  opt :agent, "Alternate user agent", :type => :string, :default => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.108 Safari/537.36'
  opt :all, "Check all domains in config"
  opt :config, "Alternate config file", :type => :string, :default => ENV['HOME'] + '/.domains.json'
  opt :content, "Check specific content", :type => :string, :default => nil
  opt :host, "Host/IP of the vhost (only if no config)", :type => :string, :default => nil
  opt :ssl, "Force SSL"
  opt :nossl, "Force without SSL"
  opt :headers, "Show all headers"
  opt :stats, "Show curl additional statistics"
  opt :commands, "Show raw command"
  opt :debug, "Show raw commands and outputs"
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
	$data = {"domains" => []}
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
		domain['hosts'].each do |host|
			puts "\t#{host}"
		end
	end
	exit
end

puts "\nChecks from ".blue + exec("GET http://ipecho.net/plain").light_blue + " - Agent: ".blue + $agent.light_blue + "\n\n"

$to_analyze = []
if $all then $to_analyze = $data['domains'] end
$urls.each do |url|
	config = findConfig($data, url)
	if config
		puts "'#{url}' found in config file".green
		$to_analyze.push(config)
	else
		puts "'#{url}' not found in config file".yellow
		domain = { "name" => url }
		if url =~ URI::regexp
			uri = URI(url)
			domain["name"] = uri.host
			domain["path"] = uri.path
			if uri.scheme == "https"
				domain["ssl"] = true
			end
		end
		$to_analyze.push(domain)
	end
end
puts

$results = {}
$threads = []
$to_analyze.each do |domain|
	$threads << Thread.new { $results[domain] = analyze_domain domain }
end
$threads.each { |thr| thr.join }
$to_analyze.each do |domain|
	if $results[domain]
		puts $results[domain]
	end
end
