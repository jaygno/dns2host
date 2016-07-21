package dns2host 

import (
        "errors"
        "math/rand"
        "time"
        "net"
        )

func readDNSResponse(c net.Conn) (*dnsMsg, error) {
	b := make([]byte, 512) // see RFC 1035
	n, err := c.Read(b)
	if err != nil {
		return nil, err
	}
	msg := &dnsMsg{}
	if !msg.Unpack(b[:n]) {
		return nil, errors.New("cannot unmarshal DNS message")
	}
	return msg, nil
}

func writeDNSQuery(c net.Conn, msg *dnsMsg) error {
	b, ok := msg.Pack()
	if !ok {
		return errors.New("cannot marshal DNS message")
	}
	if _, err := c.Write(b); err != nil {
		return err
	}
	return nil
}

func goLookupHostOrder(name string, server string) (addrs []string, err error) {
    ips, err := goLookupIPOrder(name, server)
    if err != nil {
        return
    }   
    addrs = make([]string, 0, len(ips))
    for _, ip := range ips {
        addrs = append(addrs, ip.String())
    }   
    return
}

func goLookupIPOrder(name string, server string) (addrs []net.IPAddr, err error) {
	if !isDomainName(name) {
		return nil, &net.DNSError{Err: "invalid domain name", Name: name}
	}
	type racer struct {
		rrs []dnsRR
		error
	}
	lane := make(chan racer, 1)
	//qtypes := [...]uint16{dnsTypeA, dnsTypeAAAA}
	qtypes := [...]uint16{dnsTypeA}
	var lastErr error
	for _, fqdn := range nameList(name) {
		for _, qtype := range qtypes {
			go func(qtype uint16) {
				_, rrs, err := tryOneName(server, fqdn, qtype)
				lane <- racer{rrs, err}
			}(qtype)
		}
		for range qtypes {
			racer := <-lane
			if racer.error != nil {
				lastErr = racer.error
				continue
			}
			addrs = append(addrs, addrRecordList(racer.rrs)...)
		}
		if len(addrs) > 0 {
			break
		}
	}
	if lastErr, ok := lastErr.(*net.DNSError); ok {
		// Show original name passed to lookup, not suffixed one.
		// In general we might have tried many suffixes; showing
		// just one is misleading. See also golang.org/issue/6324.
		lastErr.Name = name
	}
	//sortByRFC6724(addrs)
	if len(addrs) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
	}
	return addrs, nil
}
func nameList(name string) []string {
	// If name is rooted (trailing dot), try only that name.
	rooted := len(name) > 0 && name[len(name)-1] == '.'
	if rooted {
		return []string{name}
	}
	names := make([]string, 0, 1)
	// If name has enough dots, try unsuffixed first.
	if count(name, '.') >= 1 {
		names = append(names, name+".")
	}
	// Try unsuffixed, if not tried first above.
	if count(name, '.') < 1 {
		names = append(names, name+".")
	}
	return names
}


// Do a lookup for a single name, which must be rooted
// (otherwise answer will not find the answers).
func tryOneName(server string, name string, qtype uint16) (string, []dnsRR, error) {
	if len(name) >= 256 {
		return "", nil, &net.DNSError{Err: "DNS name too long", Name: name}
	}

	timeout := time.Duration(Timeout) * time.Second
	var lastErr error
    target := server + ":" + "53"
	msg, err := exchange(target, name, qtype, timeout)
    if err != nil {
		lastErr = &net.DNSError{
		Err:    err.Error(),
		Name:   name,
		Server: target,
        }
	    if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			lastErr.(*net.DNSError).IsTimeout = true
		}
	    return "", nil, lastErr
	}
	cname, rrs, err := answer(name, target, msg, qtype)
	if err == nil || msg.rcode == dnsRcodeSuccess || msg.rcode == dnsRcodeNameError && msg.recursion_available {
	    return cname, rrs, err
	}
	lastErr = err

	return "", nil, lastErr
}

// addrRecordList converts and returns a list of IP addresses from DNS
// address records (both A and AAAA). Other record types are ignored.
func addrRecordList(rrs []dnsRR) []net.IPAddr {
	addrs := make([]net.IPAddr, 0, 4)
	for _, rr := range rrs {
		switch rr := rr.(type) {
		case *dnsRR_A:
			addrs = append(addrs, net.IPAddr{IP: net.IPv4(byte(rr.A>>24), byte(rr.A>>16), byte(rr.A>>8), byte(rr.A))})
		case *dnsRR_AAAA:
			ip := make(net.IP, net.IPv6len)
			copy(ip, rr.AAAA[:])
			addrs = append(addrs, net.IPAddr{IP: ip})
		}
	}
	return addrs
}

func dialDNS(d net.Dialer, network, server string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	default:
		return nil, errors.New(network)
	}
	// Calling Dial here is scary -- we have to be sure not to
	// dial a name that will require a DNS lookup, or Dial will
	// call back here to translate it. The DNS config parser has
	// already checked that all the cfg.servers[i] are IP
	// addresses, which Dial will use without a DNS lookup.
	c, err := d.Dial(network, server)
	if err != nil {
		return nil, err
	}

    //add our dnsconn struct

	switch network {
	case "tcp", "tcp4", "tcp6":
		return c.(*net.TCPConn), nil
	case "udp", "udp4", "udp6":
		return c, nil
	}
	panic("unreachable")
}


func exchange(server, name string, qtype uint16, timeout time.Duration) (*dnsMsg, error) {
	d := net.Dialer{Timeout: timeout}
	out := dnsMsg{
		dnsMsgHdr: dnsMsgHdr{
			recursion_desired: true,
		},
		question: []dnsQuestion{
			{name, qtype, dnsClassINET},
		},
	}
	for _, network := range []string{"udp"} {
		c, err := dialDNS(d, network, server)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		if timeout > 0 {
			c.SetDeadline(time.Now().Add(timeout))
		}
		out.id = uint16(rand.Int()) ^ uint16(time.Now().UnixNano())
		if err := writeDNSQuery(c, &out); err != nil {
			return nil, err
		}
		in, err := readDNSResponse(c)
		if err != nil {
			return nil, err
		}
		if in.id != out.id {
			return nil, errors.New("DNS message ID mismatch")
		}
		if in.truncated { // see RFC 5966
			continue
		}
		return in, nil
	}
	return nil, errors.New("no answer from DNS server")
}
