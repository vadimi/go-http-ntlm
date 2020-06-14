# go-http-ntlm
go-http-ntlm is a Go package that contains NTLM transport (`http.RoundTripper` implementation) for `http.Client` to make NTLM auth protected http requests.

## Usage example

```go
package main

import (
    "io/ioutil"
    "log"
    "net/http"
    "strings"

    "github.com/vadimi/go-http-ntlm"
)

func main() {

    // configure http client
    client := http.Client{
        Transport: &httpntlm.NtlmTransport{
            Domain:   "mydomain",
            User:     "testuser",
            Password: "fish",
        },
    }

    req, err := http.NewRequest("GET", "http://server/ntlm-auth-resource", strings.NewReader(""))
    resp, err := client.Do(req)

    if err != nil {
        log.Fatal(err)
    }

    defer func() {
        err := resp.Body.Close()
        if err != nil {
            log.Fatal(err)
        }
    }()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Fatal(err)
    }

    log.Println(body)
}
```
