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
	if $show_commands or $debug then puts command.black.on_white end
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
	domain['hosts'].each do |host|
		threads << Thread.new {
			name = domain['name']
			out = ''

			if publicIP host
				out += indent(1, show_host(host))
				ssl = domain['ssl']
				if $force_ssl then ssl = true end
				if $no_ssl then ssl = false end

				url = 'http' + (if ssl then "s" else "" end) + '://' + name + (domain['path'] or "")
				out += indent 2, url
				o = rCurl name, publicIP(host), url
				out += indent 3, prettyCurl(o)
				if o[0]['http_code'] == '200' then
					if $content then content = $content end
					if content
						out += indent 2, "Content: "
						if o[0]['content'] =~ /#{content}/
							out += indent 3, "OK: ".light_green + content 
						else
							out += indent 3, "ERROR: ".light_red + content 
						end
						out += "\n"
					end
				end

				if ssl
					out += indent 2, "SSL: "
					out += indent 3, ssl(host, name)
				end
			else
				out += indent 1, "#{host} not found".white.on_red + "\n"
			end
			t_out[host] = out + "\n"
		}
	end
	threads.each { |thr| thr.join }
	out = show_domain(domain['name']) + "\n\n"
	domain['hosts'].each { |host| out += t_out[host] }
	return out + "\n"
end

def akamaiHost(host)
	if host =~ /edgesuite/ or host =~ /edgekey/
		if host =~ /staging/ then return "staging" else return "prod" end
	end
	false
end

def cloudflareIP?(ip)
	ip = IPAddress ip
	# https://www.cloudflare.com/ips-v4
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
	o = exec "dig #{host} | awk '/;; ANSWER SECTION:/ {getline; print}'"
	t = o.split[3]
	cn = o.split[4].chop
	if t == "CNAME"
		if tld(host) == tld(cn) 
			return _cname cn
		else
			return cn
		end
	end
	host
end

# Will NOT (by design) resolve with /etc/hosts
$to_ip_cache = {}
def publicIP(host)
	if IPAddress.valid? host then return host end
	if ! $to_ip_cache.key?(host) then $to_ip_cache[host] = _publicIP host end
	$to_ip_cache[host]
end
def _publicIP(host)
	dns = exec "host #{host}"
	dns.split("\n").each do |line|
		# XXX.in-addr.arpa has no PTR record
		# XXX.in-addr.arpa. not found: 3(NXDOMAIN)
		if line =~ /has address/ then return line.split()[3] end
	end
	false
end

def rCurl(host, ip, url)
	o = exec 'curl -sSi --compressed -H "Accept-encoding: gzip" -w \'--STATS--\n' +
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
	if m.key? 'Location'
		rCurl(host, ip, m['Location']).push(m)
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
	s.lines.each do |l|
		l.strip!
		parts = l.split(': ')
		#if parts.length == 1 then
			#o['title'] = l
		if parts.length > 1 then
			o[parts[0]] = parts[1]
		elsif l == '' then break end
	end
	show = false
	o['content'] = ''
	s.lines.each do |l|
		l.strip!
		if show == false
			if l == '--STATS--'
				show = true
			elsif
				o['content'] += l
			end
		elsif
			parts = l.split(': ')
			if parts.length > 1 then
				o[parts[0]] = parts[1]
			end
		end
	end
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
		o += cur['title'].light_green + " - " + (cur['time_total'].to_f * 1000).to_s + "ms\n"
		['Server', 'Location', 'Content-Type'].each do |col|
			if cur.key?(col)
				o += col.green + ": " + cur[col] + "\n"
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

opts = Trollop::options do
  version "Domains Checker 1.0 (c) 2016 Lorenzo Leonini"
  banner <<-EOS
Usage:
		dx [options] <config|domain|url>

where [options] are:

EOS
  opt :list, "List all domains in config (default)"
  opt :all, "Check all domains in config"
  opt :config, "Alternate config file", :type => :string, :default => nil
  opt :content, "Check specific content", :type => :string, :default => nil
  opt :host, "Host/IP of the vhost (only in command line mode)", :type => :string, :default => nil
  opt :ssl, "Force SSL"
  opt :nossl, "Force no SSL"
  opt :commands, "Show executed command"
  opt :debug, "Show all commands output"
end

$list = opts[:list]
$all = opts[:all]
$force_ssl = opts[:ssl]
$no_ssl = opts[:nossl]
$show_commands = opts[:commands]
$debug = opts[:debug]
$content = opts[:content]
$host = opts[:host]
$config = ENV['HOME'] + '/.domains.json'
if opts[:config] then $config = opts[:config] end
$d = ARGV[0]

begin
	$data = JSON.parse(File.read($config))
rescue
	puts "Config file not found: #{$config}"
	$data = {"domains" => []}
end

if $list or (!$all and !$d)
	puts "Alias/domains in config:\n\n"
	$data['domains'].each do |domain|
		if domain['alias']
			puts "#{domain['alias'].light_blue}: #{domain['name'].light_green}"
		else
			puts domain['name'].light_blue
		end
	end
	exit
end

puts ("\nChecks from " + exec("GET http://ipecho.net/plain") + "\n").light_blue

$results = {}
$threads = []
$found = false
$data['domains'].each do |domain|
	if (!$d or domain['name'] == $d or domain['alias'] == $d) and domain['hosts']
		$found = true
		$threads << Thread.new { $results[domain] = analyze_domain domain }
	end
end
$threads.each { |thr| thr.join }
$data['domains'].each do |domain|
	if $results[domain]
		puts $results[domain]
	end
end

if $d and !$found
	puts "'#{$d}' not found in config file => command line mode".light_red
	puts
	$domain = { "name" => $d }
	if $d =~ URI::regexp
		uri = URI($d)
		$domain["name"] = uri.host
		$domain["path"] = uri.path
		if uri.scheme == "https"
			$domain["ssl"] = true
		end
	end
	if !$host then $host = publicIP $domain["name"] end
	if $host
		$domain["hosts"] = [$host]
		puts analyze_domain $domain
	else
		puts "No IP found for #{$domain['name']}".white.on_red
	end
end
