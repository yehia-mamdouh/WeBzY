# WebSite Information Gthering (WeBzY)
# Created by : Yehia Mamdouh
# Date = 23/04/2014

import colorama
from colorama import Fore, Back, Style
from colorama import init

colorama.init()

print Fore.RED +  "\n"
print "\t################################################################"
print "\t#                                                              #"
print "\t#                                                              #"
print "\t#                            ###   #     #####  #   #          #"  
print "\t#            #            #  #     #        #    # #           #"
print "\t#             #    ##    #   ###   #       #      #            #"
print "\t#              #  #  #  #    #     ####   #      #             #" 
print "\t#               ##    ##     ###   ####  #####  #              #"
print "\t#                                                              #"
print "\t#                                                              #"
print "\t#                                                              #"
print "\t#                  coded by Yehia Mamdouh                      #"
print "\t#     Contact : yehiamamdouh51@hotmail.com                     #"
print "\t#                                                              #"
print "\t################################################################"
print "\t################################################################"
print "\n"
var1=0
var2=0


print Fore.CYAN + ("\n \nWebSite Information Gathering ")
print ""

import cookielib
import urllib
import urllib2
import socket
import whois
import re
import sys
import msvcrt
import smtplib
import hashlib
import urlparse
import httplib
import dns.resolver
from urllib import urlopen

#            #
colorama.init()
#            #

################################################################################

#HTTP Server Response 
def main(d):
    try:
        request = urllib2.Request(d)
        f = urllib2.urlopen(request)
        print f.geturl()
        print ""
        data = urllib2.urlopen(d)
        print data.info()
        myfile = data.read()
        print myfile
        print ""
        save = raw_input("Do you want to save? y/n: ")
        if ('y' in save):
            for i in range(1):
                orig_stdout = sys.stdout
                sa = open('HTTP.txt\n', 'w')
                sys.stdout = sa
            return 'i = ', myfile, f.geturl()
        else:
            print sys.exit(0)
    except Exception:
        return False

################################################################################


# Web Crawler 
def web(w):
    try:
        website = urllib2.urlopen(w)
        html = website.read()
        links = re.findall('"((http|ftp)s?://.*?)"', html)
        print links, "\n"
        print ""
        save = raw_input("Do you want to save? y/n: ")
        if ('y' in save):
            for i in range(1):
                orig_stdout = sys.stdout
                sw = open('WebCrawler.txt', 'w')
                sys.stdout = sw
            return links, "\n"
        else:
            print sys.exit(0)
    except Exception:
        return False
        
################################################################################


# Whois
def whois():
    try:
        whois_link = urlparse.urljoin("http://whois.net/ip-address-lookup/", z)
        source = urllib2.urlopen(whois_link).read()
        print source, "\n"
        print""
        save = raw_input ("Do you want to save> y/n: ")
        if ('y' in save):
            for i in range(1):
                orig_stdout = sys.stdout
                soo = open('Whois.txt', 'w')
                sys.stdout = soo
                return 'i = ', source, "\n"
        else:
            print sys.exit(0)
    except Exception:
        return False


################################################################################

# FTP Banner Grabbing 
def ftp(j):
    try:
        socket.setdefaulttimeout(30)
        s = socket.socket()
        s.connect((j,21))
        result = s.recv(33333)
        print result
        print ""
        save = raw_input("Do you want to save? y/n: ")
        if ('y' in save):
            for i in range(1):
                orig_stdout = sys.stdout
                sf = open('FTPBannner.txt', 'w')
                sys.stdout = sf
            return 'i = ', result
        else:
            print sys.exit(0)
    except Exception, e:
        return "[-] Error = "+str(e)

################################################################################

##Get the ip Range##
def getIPx(q):
    try:
        data = socket.gethostbyname_ex(q)
        ipx = repr(data[2])
        print ipx
        print ""
        save = raw_input("Do you want to save? y/n: ")
        if ('y' in save):
            for i in range(1):
                orig_stdout = sys.stdout
                si = open('IPRange.txt', 'w')
                sys.stdout = si
            return 'i = ', ipx
        else:
            print sys.exit(0)
    except Exception:
        # fail Too bad!
        return False

################################################################################


## Get The Domain Host##
def getHost(ip):
    try:
        data = socket.gethostbyaddr(ip)
        host = repr(data[0])
        print host
        print ""
        save = raw_input("Do you want to save? y/n: ")
        if ('y' in save):
            for i in range(1):
                orig_stdout = sys.stdout
                sh = open('Host.txt', 'w')
                sys.stdout = sh
            return 'i = ', host
        else:
            print sys.exit(0)
    except Exception:
        # fail gracefully
        return False

################################################################################


##Extract emails for the selected target##
def extractEmail(theUrl):
    request = urllib2.Request(theUrl)
    request.add_header('UserAgent', 'Ruel.ME Sample Scraper')
    response = urllib2.urlopen(request)
    for line in response.read().split('\n'):
        match = re.search(r'([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4})', line, re.I)
        if match:
            print match.group(1)
        else:
            "Not Found"

##################################################################################

            
# Send mail via Gmail
def smtp():
    print ""
    print Fore.CYAN + """Send a simple mail to Gmail
countine an info that you get from WeBzY
Enter your mail adress , Recv adress , user and pass"""
    print ""
    fromaddr = raw_input("Enter your mail addres: ")
    toaddrs = raw_input("Enter recv adress: ")
    msg = raw_input("Enter your message: ")
    username = raw_input("Enter you username: ")
    password= raw_input("Enter your password: ")
    server = smtplib.SMTP('smtp.gmail.com:587')
    server.starttls()
    server.login(username,password)
    server.sendmail(fromaddr, toaddrs, msg)
    server.quit()


#################################################################################


# Crack MD5 Hashes Via Wordlist
def has():
    print ""
    print Fore.RED + """MD5 hashes crack , it depend on wordlist
Hashes should be stored in txt file in
the same directory and wordlist too """
    print ""
    hh = hashlib.md5()
    has = ""
    hash_file = raw_input("Enter name of txt that coutnie hashes?  ")
    wordlist = raw_input("What is your wordlist?  (Enter the file name)  ")
    try:
        hashdocument = open(hash_file,"r")
    except IOError:
        print "Invalid file."
        raw_input()
        sys.exit()
    
    else:
        has = hashdocument.readline()
        has = has.replace("\n","")
	
    try:
        wordlistfile = open(wordlist,"r")
    except IOError:
        print "Invalid file."
        raw_input()
        sys.exit()
    
    else:
        pass
        for line in wordlistfile:
            hh = hashlib.md5()
	    line = line.replace("\n","")
	    hh.update(line)
	    word_hash = hh.hexdigest()
	    if word_hash==has:
                print "Great!  The word match to the given hash is", line,
	        raw_input()
	        sys.exit()
                print "The hash given does not Match to any word in the wordlist."
                raw_input()
                sys.exit()

###############################################################################


def Dns():
    try:
        print ""
        print "Example : google.com
        ans = raw_input("Enter Doamin name: ")
        answers = dns.resolver.query(ans, 'MX')
        answers1 = dns.resolver.query(ans, 'A')
        answers2 = dns.resolver.query(ans, 'AAAA')
        answers3 = dns.resolver.query(ans, 'NS')
        for rdata in answers:
            print ""
            print Fore.RED + "MX Rec"
            print 'Host', rdata.exchange, 'has preference', rdata.preference
        for radata in answers1:
            print ""
            print Fore.CYAN + "A Rec"
            print 'Host', rdata.exchange, 'has preference', rdata.preference
        for radata in answers2:
            print ""
            print Fore.YELLOW + "AAAA Rec"
            print 'Host', rdata.exchange, 'has preference', rdata.preference
        for radata in answers3:
            print ""
            print Fore.BLUE + "NS Rec"
            print 'Host', rdata.exchange, 'has preference', rdata.preference
    except Exception:
        # fail Too bad!
        return False


#######################################################################################

def DnsStatus():
    try:
        print ""
        print "Example : google.com"
        print ""
        dn = raw_input("Enter domain name: ")
        roo = urllib2.urlopen("http://www.intodns.com/" + dn)
        ree =  roo.read()
        print ree
        save = raw_input("Do you want to save? y/n: ")
        if ('y' in save):
            for i in range(1):
                orig_stdout = sys.stdout
                ruu = open('DNS.html', 'w')
                sys.stdout = ruu
                return 'i = ', ree
        
        else:
            print sys.exit(0)
    except Exception:
        return False

######################################################################################

def PassiveDNS():
    try:
        print ""
        print "Example : google.com, NS53.DOMAINCONTROL.COM"
        print ""
        dnn = raw_input("Enter domain name: ")
        goo = urllib2.urlopen("http://www.bfk.de/bfk_dnslogger.html?query=" + dnn)
        gee =  goo.read()
        print "\n[!] LINKS:", gee,"\n"
        save = raw_input("Do you want to save? y/n: ")
        if ('y' in save):
            for i in range(1):
                orig_stdout = sys.stdout
                ruu = open('DNS.html', 'w')
                sys.stdout = ruu
                return 'i = ', gee
        
        else:
            print sys.exit(0)
    except Exception:
        return False

##Write a Domain without http or https##
z = raw_input("Enter Domain Name: ")
ree  = ("http://" +z)

print Fore.YELLOW + (30 * '-')
print ("   W E B Z Y - M E N U")
print (30 * '-')
print ("1. Server Response")
print ("2. Web Crawler")
print ("3. Whois")
print ("4. FTP Banner")
print ("5. IP Range")
print ("6. Web Host")
print ("7. Mails Harvest")
print ("8. Send Gmail")
print ("9. MD5 Crack")
print ("10.DNS Query")
print ("11.DNS Status")
print ("12. Passive DNS")



## Get input ###
print ""
choice = raw_input('Enter your choice [1-12] : ')
 
### Convert string to int type ##
choice = int(choice)
 
### Pick up a choice for the menu ###
if choice == 1:
    print ""
    print "Server Response" ,  main(ree)
elif choice == 2:
    print "Web Crawler" , web(ree)
elif choice == 3:
    print "whois", whois()
elif choice == 4:
    print ""
    print "FTP Banner", ftp(z)
elif choice == 5:
    print "IP Range" , getIPx(z)
elif choice == 6:
    print "Web Host", getHost(z)
elif choice == 7:
    print "mails", extractEmail(ree)
elif choice == 8:
    print "Gmail", smtp()
elif choice == 9:
    print "MD5 Crack", has()
elif choice == 10:
    print ""
    print "Get (Mx, A, AAAA, NS) Records ", Dns()
    print ""
elif choice == 11:
    print""
    print "DNS Status", DnsStatus()
    print""
elif choice == 12:
    print ""
    print "Passive DNS Result", PassiveDNS()
else:
    print ("Invalid number. Try again...")



