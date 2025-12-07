package resolver

// GetServiceName returns the service name for a port/protocol combination
// protocol: 6=TCP, 17=UDP
func GetServiceName(port uint16, protocol uint8) string {
	if port == 0 {
		return ""
	}

	// Check protocol-specific first
	if protocol == 6 { // TCP
		if name, ok := tcpServices[port]; ok {
			return name
		}
	} else if protocol == 17 { // UDP
		if name, ok := udpServices[port]; ok {
			return name
		}
	}

	// Fall back to common services (same for TCP/UDP)
	if name, ok := commonServices[port]; ok {
		return name
	}

	return ""
}

// GetServiceByPort returns service name regardless of protocol
func GetServiceByPort(port uint16) string {
	if name, ok := commonServices[port]; ok {
		return name
	}
	if name, ok := tcpServices[port]; ok {
		return name
	}
	if name, ok := udpServices[port]; ok {
		return name
	}
	return ""
}

// IsKnownService checks if a string is a known service name
func IsKnownService(name string) bool {
	for _, svc := range commonServices {
		if svc == name {
			return true
		}
	}
	for _, svc := range tcpServices {
		if svc == name {
			return true
		}
	}
	for _, svc := range udpServices {
		if svc == name {
			return true
		}
	}
	return false
}

// Common services (same port for TCP and UDP)
var commonServices = map[uint16]string{
	7:     "echo",
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	67:    "dhcp-s",
	68:    "dhcp-c",
	69:    "tftp",
	80:    "http",
	88:    "kerberos",
	110:   "pop3",
	119:   "nntp",
	123:   "ntp",
	135:   "msrpc",
	137:   "netbios-ns",
	138:   "netbios-dgm",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	162:   "snmp-trap",
	179:   "bgp",
	389:   "ldap",
	443:   "https",
	445:   "smb",
	464:   "kpasswd",
	465:   "smtps",
	500:   "isakmp",
	514:   "syslog",
	515:   "printer",
	520:   "rip",
	546:   "dhcpv6-c",
	547:   "dhcpv6-s",
	587:   "submission",
	636:   "ldaps",
	853:   "dns-tls",
	873:   "rsync",
	902:   "vmware",
	989:   "ftps-data",
	990:   "ftps",
	993:   "imaps",
	995:   "pop3s",
	1080:  "socks",
	1194:  "openvpn",
	1433:  "mssql",
	1434:  "mssql-m",
	1521:  "oracle",
	1701:  "l2tp",
	1723:  "pptp",
	1812:  "radius",
	1813:  "radius-acct",
	1883:  "mqtt",
	2049:  "nfs",
	2082:  "cpanel",
	2083:  "cpanel-ssl",
	2086:  "whm",
	2087:  "whm-ssl",
	2181:  "zookeeper",
	2222:  "ssh-alt",
	2375:  "docker",
	2376:  "docker-ssl",
	3000:  "grafana",
	3128:  "squid",
	3268:  "gc",
	3269:  "gc-ssl",
	3306:  "mysql",
	3389:  "rdp",
	3690:  "svn",
	4000:  "remoteanything",
	4443:  "https-alt",
	4500:  "ipsec-nat",
	4567:  "tram",
	5000:  "upnp",
	5060:  "sip",
	5061:  "sips",
	5222:  "xmpp-c",
	5269:  "xmpp-s",
	5432:  "postgres",
	5672:  "amqp",
	5900:  "vnc",
	5938:  "teamviewer",
	5984:  "couchdb",
	5985:  "winrm",
	5986:  "winrm-ssl",
	6379:  "redis",
	6443:  "k8s-api",
	6514:  "syslog-tls",
	6667:  "irc",
	6697:  "irc-ssl",
	7001:  "weblogic",
	7002:  "weblogic-ssl",
	8000:  "http-alt",
	8008:  "http-alt",
	8080:  "http-proxy",
	8081:  "http-alt",
	8123:  "polipo",
	8140:  "puppet",
	8443:  "https-alt",
	8444:  "https-alt",
	8500:  "consul",
	8888:  "http-alt",
	9000:  "php-fpm",
	9001:  "tor-orport",
	9042:  "cassandra",
	9090:  "prometheus",
	9091:  "transmission",
	9092:  "kafka",
	9100:  "jetdirect",
	9200:  "elasticsearch",
	9300:  "elasticsearch",
	9418:  "git",
	9993:  "zerotier",
	9999:  "abyss",
	10000: "webmin",
	10050: "zabbix-agent",
	10051: "zabbix",
	10443: "https-alt",
	11211: "memcached",
	11371: "hkp",
	15672: "rabbitmq-mgmt",
	17500: "dropbox",
	25565: "minecraft",
	27017: "mongodb",
	27018: "mongodb",
	28015: "rethinkdb",
	32400: "plex",
	49000: "tr-064",
	50000: "sap",
	51413: "bittorrent",
}

// TCP-specific services
var tcpServices = map[uint16]string{
	1:     "tcpmux",
	9:     "discard",
	13:    "daytime",
	37:    "time",
	79:    "finger",
	109:   "pop2",
	111:   "rpcbind",
	113:   "ident",
	465:   "smtps",
	513:   "rlogin",
	543:   "klogin",
	544:   "kshell",
	1099:  "rmiregistry",
	2000:  "cisco-sccp",
	2001:  "dc",
	2010:  "search",
	4444:  "krb524",
	5631:  "pcanywheredata",
	8009:  "ajp13",
	8291:  "mikrotik",
}

// UDP-specific services
var udpServices = map[uint16]string{
	7:     "echo",
	9:     "discard",
	13:    "daytime",
	37:    "time",
	111:   "rpcbind",
	177:   "xdmcp",
	427:   "svrloc",
	443:   "quic",
	500:   "isakmp",
	514:   "syslog",
	517:   "talk",
	518:   "ntalk",
	520:   "rip",
	521:   "ripng",
	623:   "ipmi",
	1194:  "openvpn",
	1645:  "radius-old",
	1646:  "radacct-old",
	1900:  "ssdp",
	3478:  "stun",
	3544:  "teredo",
	4380:  "teredo-alt",
	4500:  "ipsec-nat",
	4789:  "vxlan",
	5004:  "rtp",
	5005:  "rtcp",
	5353:  "mdns",
	5355:  "llmnr",
	6081:  "geneve",
	8472:  "vxlan-otv",
}
