import subprocess, re

#sp = subprocess.call(["ls", "-l"])
data = """24:73:8c:64 (oui Unknown) Beacon (uofm-wpa) [1.0* 2.0* 5.5* 6.0 9.0 11.0* 12.0 18.0 Mbit] ESS CH: 1, PRIVACY[|802.11]
13:13:55.909728 423007425us tsft 1.0 Mb/s 2412 MHz 11g -89dB signal -89dB noise antenna 0 BSSID:Broadcast DA:Broadcast SA:00:00:85:ea:30:18 (oui Unknown) Probe Request (BJNPSETUP) [1.0* 2.0* 5.5* 11.0* 6.0 9.0 12.0 18.0 Mbit][|802.11]
13:13:55.927313 423024192us tsft bad-fcs 1.0 Mb/s 2412 MHz 11g -90dB signal -89dB noise antenna 0 BSSID:00:12:01:88:7f:73 (oui Unknown) DA:Broadcast SA:00:12:01:88:7f:73 (oui Unknown) Beacon ESS[|802.11]
13:13:55.930449 423027335us tsft 1.0 Mb/s 2412 MHz 11g -68dB signal -89dB noise antenna 0 BSSID:00:0f:24:73:8c:63 (oui Unknown) DA:Broadcast SA:00:0f:24:73:8c:63 (oui Unknown) Beacon (uofm) [1.0* 2.0* 5.5* 6.0 9.0 11.0* 12.0 18.0 Mbit] ESS CH: 1[|802.11]"""

print data


def tcpdump():
	cmd1 = ["sudo", "tcpdump", "-i", "en1", "-I", "-e"]
	
	p1 = subprocess.Popen(cmd1, stdout=subprocess.pipe)

	flags = fcntl.fcntl(p1.stdout.fileno(), fcntl.F_GETFL)
	fcntl.fcntl(p1.stdout.fileno(), fcntl.F_SETFL, (flags | O_NDELAY | O_NONBLOCK))

	return p1


def parse(data):
	# pat = re.compile(r"""
	# 	(?P<line>^(									#for each new line
	# 	(?P<time>\d{2}:\d{2}:\d{2}\.\d{6} \d{9}us)	#match time pattern
	# 	.+?\s11g\s									#then drop filler
	# 	(?P<rssi>-?\d+\sdB)							#until rssi pattern shows up
	# 	\ssignal.+?									#then more filler
	# 	(?P<bssid>:{5})						#until bssid pattern (MAC address) shows up
	# 	.+?											#then more filler
	# 	(?P<source>:{5})					#until source MAC address
	# 	).+?$										#until end of line
	# 	)
	# """, re.VERBOSE) ###

	pat = re.compile(""c""")

	result = pat.search(data).group(0)
	return result

print parse(data)

