#!/usr/bin/ruby
"""
@Author	:	CyanLine LLC
@Date	:	April 25, 2013
@Name	:	nbeparse.rb
@Desc	:	This takes a NBE file organizes it and prints the organized data to standard out.
@Usage	:	ruby nbeparse.rb <args> <nbe output>

"""

TYPE = 5
PORT = 3
DESCRIPTION = 6
NUMBER = 4
IP = 2

# Provide usage instructions
# methods
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

# Check if the user wants this result type logged for the final report
def log_result?(type)
    
    if ($all == true) || (type == "Log Message" && $logs == true) || (type == "Security Hole" && $holes == true) || (type == "Security Note" && $notes == true) || (type == "Security Warning" && $warnings == true) 
        return true
    end

    return false

end

# If the user indicated they only want to see results from one IP address this
# will parse the input to ensure that it is a properly formated IP and set the
# $onlyip variable for use later.  If it's not valid we will print usage and
# exit
def only_ip()

    ip = ARGV[0]

    ipv4 = /^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$/
   ipv6 = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/ 

    if ip =~ ipv4 || ip =~ ipv6
        $onlyip = ip
        ARGV.shift
    else
        usage()
    end

end

# Log the number of times each result type occurs
def log_type(type)
    if type == "Security Hole"
        $holeCount = $holeCount + 1
    elsif type == "Log Message"
        $logCount = $logCount + 1
    elsif type == "Security Note"
        $noteCount = $noteCount + 1
    elsif type == "Security Warning"
        $warningCount = $warningCount + 1
    else
        $miscCount = $miscCount + 1
    end
end

# Collect and organize data from the raw nbe output
def collect()

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

                type = vuln[TYPE]
                port = vuln[PORT]
                descriptions = vuln[DESCRIPTION].split("\\n")
                number = vuln[NUMBER]
                ip = vuln[IP]
            
                # Check if the user wants this result logged
                if log_result?(type) 

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

                        # Log what type of vulnerability this is for display
                        # later
                        log_type(type)
    
	    			    info = [type, port, descriptions]
		    		    $descriptions[number].push(info)
			        end
                end
		    end
	    end
    end 
end

# Print the final report
def print_findings()

    # Print totals
    puts "Total Findings: #{$findings.size}"
    puts "======================"
    puts "Log Messages: #{$logCount}"
    puts "Security Notes: #{$noteCount}"
    puts "Security Warnings: #{$warningCount}"
    puts "Security Holes: #{$holeCount}"
    puts "Other Findings: #{$miscCount}"
    puts

    # Print each finding
    $findings.each do |key, value|
        print "==> "
	    puts key
	    puts $descriptions[key]

        # If we are printing results with IP addresses
        if $noip == false then
            # Print out all IP addresses for each result
            puts "Host(s) :"
	        value.each do |e|
                puts e
	        end
        end
        # Seperator
        2.times do puts end
        puts "============================================================="
        2.times do puts end
    end

end


# Run

puts """

NBEParse

(c) 2013 CyanLine LLC
http://cyanline.com

"""

# Set default values for globals

$logs = false
$notes = false
$holes = false
$warnings = false
$all = false

$noip = false
$onlyip = ""


# Parse arguments
loop { case ARGV[0]
    when '-a' then ARGV.shift; $all = true
    when '-l' then ARGV.shift; $logs = true
    when '-n' then ARGV.shift; $notes = true
    when '-h' then ARGV.shift; $holes = true
    when '-w' then ARGV.shift; $warnings = true
    when '-ni' then ARGV.shift; $noip = true
    when '-i' then ARGV.shift; only_ip()
    when /^-/ then usage()
    else break
end; }

if $logs == false && $notes == false && $holes == false && $warnings == false && $all == false then
    $all = true
end

# User didnt supply enough information
if ARGV.size != 1 then
    usage()
end
                                                               
# global finding db
$findings = Hash.new {|h, k| h[k] = Array.new}

# global descriptions db
$descriptions = Hash.new {|h, k| h[k] = Array.new}

$holeCount = 0
$logCount = 0
$noteCount = 0
$warningCount = 0
$miscCount = 0

# Collect and organize all vulnerabilities
collect()

# Print out results
print_findings()
