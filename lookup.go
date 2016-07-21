package dns2host 

import (
        "errors"
        "net"
        )

// LookupHost looks up the given host using the local resolver.
// It returns an array of that host's addresses.
var  (
     Timeout = 10 
     errNoSuchHost = errors.New("no such host")
     )

func LookupHost(server string, host string) (addrs []string, err error) {
    // Make sure that no matter what we do later, host=="" is rejected.
    // ParseIP, for example, does accept empty strings.
    if host == "" {
        return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host}
    }
    if ip := net.ParseIP(host); ip != nil {
        return []string{host}, nil
    }
    return lookupHost(server, host)
}


func lookupHost(server string, host string) (addrs []string, err error) {
    return goLookupHostOrder(host, server)
}
