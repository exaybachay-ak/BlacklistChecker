# IP Address Audit 
#  Script to scrape together all Windows log artifacts for IP addresses and scan them to make a report of potential issues 

#$ippattern = "{1-2}+{1-9}+{1-9}+\.{1-2}+{1-9}+{1-9}+\.{1-2}+{1-9}+{1-9}+\.{1-2}+{1-9}+{1-9}+"
$ippattern = "\d+\.\d+\.\d+\.\d+"

# Gather IP info
$allipinfo = @()

# Look for cached information and active connections
$allipinfo += Get-NetTCPConnection
$allipinfo += Ipconfig /displaydns 

# Try to find IP addresses in security logs

$secevents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156,5158,4688}
$allipinfo += $seceventips

# If sysmon is installed, look there for IP addresses 
$sysmonevents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3,22 }
$allipinfo += $sysmoneventips

# Check Windows Defender logs
$defenderevents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117,5007 }
$allipinfo += $defendereventips

# Check DNS Client logs 
$dnsevents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=3006,3010 }
$allipinfo += $dnsevents

# Check the IP info for external IP addresses
if($allipinfo){
    if($allipinfo -match $ippattern){
        # Extract IPs
        $ips = (($allipinfo | select-string -pattern $ippattern).matches.value | sort -unique)

        # Lazily filter out local addresses NOTE: should try to improve this in the future with accurate private ip ranges
        $ips = $ips | Where { $_ -notlike "0.0.0.0" -and $_ -notlike "127.*" -and $_ -notlike "192.168.*" -and $_ -notlike "10.*" -and $_ -notlike "172.16.*" -and $_ -notlike "255.*" -and $_ -notlike "224.*"}

        # Add ip info to array for gathering ip intel later
        $allips += $ips
    }
}

# Search open source intelligence for potential issues associated with IPs 
$ipsumblacklistips = @()
$blacklistippattern = "\d+\.\d+\.\d+\.\d+.*"
$ipsumblacklist = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt'
$ipsumblacklistips += ($ipsumblacklist.content | Select-String -pattern $blacklistippattern ).matches.value

# Blocklist.de fail2ban reporting service 
$bruteforce = (Invoke-WebRequest -Uri 'https://lists.blocklist.de/lists/bruteforcelogin.txt').content
$ircbots = (Invoke-WebRequest -Uri 'https://lists.blocklist.de/lists/ircbot.txt').content
$strongips = (Invoke-WebRequest -Uri 'https://lists.blocklist.de/lists/strongips.txt').content
$bots = (Invoke-WebRequest -Uri 'https://lists.blocklist.de/lists/bots.txt').content
$sipbots = (Invoke-WebRequest -Uri 'https://lists.blocklist.de/lists/sip.txt').content
$ftp = (Invoke-WebRequest -Uri 'https://lists.blocklist.de/lists/ftp.txt').content
$imap = (Invoke-WebRequest -Uri 'https://lists.blocklist.de/lists/imap.txt').content
$apache = (Invoke-WebRequest -Uri 'https://lists.blocklist.de/lists/apache.txt').content
$mail = (Invoke-WebRequest -Uri 'https://lists.blocklist.de/lists/mail.txt').content
$ssh = (Invoke-WebRequest -Uri 'https://lists.blocklist.de/lists/ssh.txt').content
$all = (Invoke-WebRequest -Uri 'https://lists.blocklist.de/lists/all.txt').content

$fulllist = $all + $ipsumblacklist

# Check each detected IP against the full blacklist
$allips | % {
    Write-output "Scanning $_ ..."
    if($fulllist -contains $_){
        Write-host -foregroundcolor Red "Detected a suspicious IP - please investigate $_ "
    }
}
