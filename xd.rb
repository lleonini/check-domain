#!/usr/bin/ruby
require 'colorize'
require 'uri'
require 'htmlentities'
require 'json'
require 'net/http'
require 'ipaddress'


def exec(command)
	o = `#{command}`
	return o
end

def show_host(host)
	if (host =~ /edgesuite/ or host =~ /edgekey/) then
		if host =~ /staging/ then
			return "<AKAMAI Staging>".cyan
		else
			return "<AKAMAI Prod>".light_magenta
		end
	end
	ip = toIP(host)
	if host =~ /clara.net/ or exec("host #{ip}") =~ /clara.net/ then
		if host == ip then
			return "<CLARANET: #{host}>".light_yellow
		else
			if ip then
				return "<CLARANET: #{host} #{ip}>".light_yellow
			else
				return "<CLARANET: #{host} domain not existing ?>".light_yellow.on_red
			end
		end
	end
	if host == ip then
		return "<#{host}>".light_yellow
	else
		if ip then
			return "<#{host} #{ip}>".light_yellow
		else
			return "<#{host} domain not existing ?>".light_yellow.on_red
		end
	end
end

def show_domain(name)
	ip_dns = toIP(name)
	ip_local = localIP(name)
	o = "#{name.white.on_blue}"
	if ip_dns then
		if ip_dns == ip_local then
			return o + " - DNS IP: #{ip_dns.black.on_green}"
		else
			return o + " - DNS IP: #{ip_dns.black.on_green} - Local IP: #{ip_local.white.on_red}"
		end
	else
		return o + " - " + " domain not existing ? ".white.on_red
	end
end

def analyze_domain(domain)
	t_out = {}
	threads = []
	domain['hosts'].each {|host|
		threads << Thread.new {
			name = domain['name']
			out = indent(1, show_host(host))

			if domain['ssl'] then
				url = 'https://' + name + domain['path']
			else
				url = 'http://' + name + domain['path']
			end
			out += indent(2, url)
			o = headers(name, host, url)
			if o =~ /200 OK/ then
				o.lines.each { |l|
					l.strip!
					if l =~ /HTTP\// or l =~ /Server: / or l =~ /Location: / then
						out += indent(3, l.light_green)
					end
				}
				out += indent(2, "Content: ")
				body = body(name, host, url)
				if body =~ /#{domain['content']}/ then
					out += indent(3, "OK: ".light_green + domain['content']) 
				else
					out += indent(3, "ERROR: ".light_red + domain['content']) 
				end
			else
				if o =~ /HTTP\// then
					out += indent(3, o.strip.light_red)
				else
					out += indent(3, o.strip.white.on_red)
				end
			end

			if domain['ssl'] then
				out += indent(2, "SSL: ")
				out += indent(3, ssl(host, name))
			end
			t_out[host] = out + "\n"
		}
	}
	threads.each { |thr| thr.join }
	out = show_domain(domain['name']) + "\n\n"
	domain['hosts'].each { |host| out += t_out[host] }
	return out + "\n"
end
	
def localIP(host)
	o = exec("getent ahosts #{host}")
	if o.length > 1 then
		return o.lines[0].split(' ')[0]
	else
		return false
	end
end

$to_ip_cache = {}
def toIP(host)
	if IPAddress.valid? host then
		return host
	end
	if ! $to_ip_cache.key?(host) then
		$to_ip_cache[host] = _toIP(host)
	end
	return $to_ip_cache[host]
end
def _toIP(host)
	dns = exec("host #{host}")
	dns.split("\n").each do |line|
		# XXX.in-addr.arpa has no PTR record
		# XXX.in-addr.arpa. not found: 3(NXDOMAIN)
		if line =~ /has address/ then
			return line.split()[3]
		end
	end
	return false
end

def headers(host, ip, url)
	ip = toIP(ip)
	return exec("curl -sSLI --resolve #{host}:80:#{ip} --resolve #{host}:443:#{ip} #{url} 2>&1")
end

def body(host, ip, url)
	ip = toIP(ip)
	return exec("curl -sSL --resolve #{host}:80:#{ip} --resolve #{host}:443:#{ip} #{url} 2>&1")
end

def indent(level, s)
	l = 0
	i = ""
	while l < level
		i +=  "  "
		l += 1
	end
	o = ""
	s.lines.each {|l|
		o += i + l.strip.gsub("\n",'') + "\n"
	}
	return o
end

def ssl(ip, domain)
	o = exec("openssl s_client -showcerts -servername #{domain} -connect #{ip}:443 2>&1 >/dev/null </dev/null")
	ok = true
	if o =~ /unable to/ or o=~ /verify error/ then
		ok = false
	end
	o.lines.each {|l|
		if l =~ /depth=0/ then
			if ok then
				return l.gsub("\n",'').light_green
			else
				return l.gsub("\n",'').light_red
			end
		end
	}
	return o.lines[0].gsub("\n",'').white.on_red
end

puts ("Checks from " + exec("GET http://ipecho.net/plain"))
puts

file = File.read('domains.json')
data = JSON.parse(file)

d = ARGV[0]

#data['domains'].each {|domain|
	#if !d or domain['name'] == d then
		#puts analyze_domain(domain)
	#end
#}

results = {}
threads = []
data['domains'].each {|domain|
	if !d or domain['name'] == d then
		threads << Thread.new {
			results[domain] = analyze_domain(domain)
		}
	end
}
threads.each { |thr| thr.join }
data['domains'].each {|domain|
	if results[domain] then
		puts results[domain]
	end
}
