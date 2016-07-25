#!/usr/bin/ruby
require 'colorize'
require 'uri'
require 'htmlentities'
require 'json'
require 'net/http'
require 'pp'

def fetch(url)
	res = fetch_follow(url)
	if res.code.to_i == 200 then
		c = res.code.to_s.light_green
	else
		c = res.code.to_s.light_red
	end
	
	if url.to_s == res.uri.to_s then
		return "#{c} #{res.uri}"
	else
		return "#{c} #{url} => #{res.uri}"
	end
end

def fetch_follow(url)
	res = Net::HTTP.get_response(URI.parse(url.to_s))
	if res.code.to_i == 301 then
		return fetch_follow(res['location'])
	else
		return res
	end
end

def findIp(domain)
	dns = `host #{domain}`
	public_ips = []
	dns.split("\n").each do |line|
		if line =~ /has address/ then
			return line.split()[3]
		end
		# already an IP
		if line =~ /domain name pointer/ then
			return domain
		end
	end
	return false
end

def reverse(ip)
	r = `dig +noall +answer -x #{ip}`
	if r != "" then
		return r.split()[4]
	end
	return ip
end

def indent(level, s)
	l = 0
	o = ""
	while l < level
		o +=  "  "
		l += 1
	end
	s.lines.each {|l|
		puts o + l
	}
end

def ssl(ip, domain)
	o = `openssl s_client -showcerts -servername #{domain} -connect #{ip}:443 2>&1 >/dev/null </dev/null`
	ok = true
	if o =~ /unable to/ then
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
end

puts ("Checks done from " + `GET http://ipecho.net/plain`).blue.on_white
puts

file = File.read('domains.json')
data = JSON.parse(file)

data['domains'].each {|domain|
	name = domain['name']
	puts "Domain: #{name.light_blue}"
	puts
	domain['hosts'].each {|host|
		indent(1, "Host: #{host.light_yellow} (#{findIp(host)})")
		puts

		indent(2, "Content: ") 
		url = 'http://' + name + domain['path']
		c = "curl -sSLI --resolve #{name}:80:#{host} #{url} 2>&1"
		o = `#{c}`
		if o =~ /HTTP\// then
			o.lines.each { |l|
				l.strip!
				if l =~ /HTTP\// or l =~ /Server: / or l =~ /Location: / then
					if o =~ /200 OK/ then
						indent(3, l.light_green)
					else
						indent(3, l.light_red)
					end
				end
			}
		else
			indent(3, o.strip.white.on_red)
		end

		puts
		indent(2, "SSL: " + ssl(host, name)) 
		puts
	}
}
