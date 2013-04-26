#!/usr/bin/ruby
"""
@Author	:	CyanLine LLC
@Date	:	April 25, 2013
@Name	:	nbeparse.rb
@Desc	:	This takes a NBE file organizes it and prints the organized data to standard out.
@Usage	:	ruby nbeparse.rb <nbe output>

"""

puts """

NBEParse

(c) 2013 CyanLine LLC
http://cyanline.com

"""
if ARGV.size != 1 then

	puts "Usage: ruby nbeparse.rb <nbe output>"
	exit
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

			# Add the ip address to the findings hash and use
			# the result number as the key
			$findings[vuln[4]].push(vuln[2])

			# Store descriptions once in a seperate hash
			# if the description for this result number
			# alread exists don't store it again
			if !$descriptions.has_key?(vuln[4])
			#	vuln[6].gsub!("\\n", " ")
                descriptions = vuln[6].split("\\n")
                descriptions.each do | line |
                    line.gsub!("\\r", " ")
                end
				info = [vuln[5], vuln[3], descriptions]
				$descriptions[vuln[4]].push(info)
			end
		end
	end
end

# Print everything in a readable manner
$findings.each do |key, value|
    print "==> "
	puts key
	puts $descriptions[key]
    puts "Host(s) :"
	value.each do |e|
		puts e
	end
    2.times do puts end
end

