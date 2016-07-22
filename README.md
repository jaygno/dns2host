# dns2host
resolve the A record by the target host, support A type only.

[![Build Status](https://travis-ci.org/jaygno/dns2host.svg?branch=master)]


# Features

* Specify the target host;
* UDP queries, IPv4;
* Depends only on the standard library.

Have fun!

# Installing

    go get github.com/jaygno/dns2host
    go build github.com/jaygno/dns2host

## Examples

```go
>package main

>import(
       "fmt"
       "github.com/dns2host"
      )


>func main() {
    ips, _ := dns2host.LookupHost("114.114.114.114", "www.baidu.com")
    fmt.Println(ips) 
}
```
##Next Plan
* Support ipv6;
* Support Tcp;

