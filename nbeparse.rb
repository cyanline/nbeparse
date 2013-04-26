#!/usr/bin/ruby
"""
@Author	:	CyanLine LLC
@Date	:	April 25, 2013
@Name	:	nbeparse.rb
@Desc	:	This takes a NBE file organizes it and prints the organized data to standard out.
@Usage	:	ruby nbeparse.rb <args> <nbe output>

"""

puts """

NBEParse

(c) 2013 CyanLine LLC
http://cyanline.com

"""

def usage()
    $stderr.puts "Uasge: ruby nbeparse <args> <nbe output>"
    $stderr.puts
    $stderr.puts "Arguments:"
    $stderr.puts "-l  Display log message results"
    $stderr.puts "-h Display security holde results"
    $stderr.puts "-n Display security note results"
    $stderr.puts "-w Display security warning results"
    $stderr.puts "-ni Display results but don't display IP addresses"
    $stderr.puts "-i <ip address> Display only results with the given IP address"
    exit(2)
end

# Check if the user wants this result type logged
def logResult?(type)
    
    if $all == true
        return true
    elsif type == "Log Message" && $logs == true
        return true
    elsif type == "Security Hole" && $holes == true
        return true
    elsif type == "Security Note" && $notes == true
        return true
    elsif type == "Security Warning" && $warnings == true
        return true
    end

    return false

end

def onlyIP()

    ip = ARGV[0]

    ipv4 = /^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$/
   ipv6 = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/ 

    if ip =~ ipv4 || ip =~ ipv6 then
        ARGV.shift
    else
        usage()
    end

end

$logs = false
$notes = false
$holes = false
$warnings = false
$all = false

$noip = false
$onlyip = ""

loop { case ARGV[0]
    when '-a' then ARGV.shift; $all = true
    when '-l' then ARGV.shift; $logs = true
    when '-n' then ARGV.shift; $notes = true
    when '-h' then ARGV.shift; $holes = true
    when '-w' then ARGV.shift; $warnings = true
    when '-ni' then ARGV.shift; $noip = true
    when '-i' then ARGV.shift; onlyIP()
    when /^-/ then usage()
    else break
end; }

if $logs == false && $notes == false && $holes == false && $warnings == false && $all == false then
    $all = true
end

if ARGV.size != 1 then
    usage
end
                                                               
# global finding db
$findings = Hash.new {|h, k| h[k] = Array.new}
$descriptions = Hash.new {|h, k| h[k] = Array.new}


filename = ARGV[0]
puts "[-] opening #{filename}"
puts
f = File.open(filename, "r") # user input

f.each_with_index do |line, index|
	# don't do any of this if the line is nil
	if line != nil then
        vuln = line.split('|')
		# Time Stamps had a array length of 4 and we dont really 
		# care to see timestamps
		# We want only results
		# In some cases the results provided no information and the
		# second line was blank so we got rid of them
		if vuln.size > 4  && vuln[0] == 'results' && vuln[1] != ''  then

            type = vuln[5]
            port = vuln[3]
            descriptions = vuln[6].split("\\n")
            number = vuln[4]
            ip = vuln[2]
            
            # Check if the user wants this result logged
            if logResult?(type) 

			    # Add the ip address to the findings hash and use
			    # the result number as the key
                
                if $onlyip.length > 1
                    if $onlyip == ip then
			            $findings[number].push(ip)
                    end
                else
			        $findings[number].push(ip)
                end
    
	    		# Store descriptions once in a seperate hash
		    	# if the description for this result number
			    # alread exists don't store it again
			    if !$descriptions.has_key?(number)

                    descriptions.each do | line |
                        line.gsub!("\\r", " ")
                    end

    
	    			info = [type, port, descriptions]
		    		$descriptions[number].push(info)
			    end
            end
		end
	end
end

# Print everything in a readable manner
$findings.each do |key, value|
    print "==> "
	puts key
	puts $descriptions[key]
    if $noip == false then
        puts "Host(s) :"
	    value.each do |e|
            puts e
	    end
    end
    2.times do puts end
end
