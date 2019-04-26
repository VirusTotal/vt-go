[![GoDoc](https://godoc.org/github.com/VirusTotal/vt-go?status.svg)](https://godoc.org/github.com/VirusTotal/vt-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/VirusTotal/vt-go)](https://goreportcard.com/report/github.com/VirusTotal/vt-go)


# vt-go

This is the official Go client library for VirusTotal. With this library you can
interact with the VirusTotal REST API v3 without having to send plain HTTP requests
with the standard "http" package.

## Usage example

```golang

import (
    "flag"
    "fmt"
    "log"

    vt "github.com/VirusTotal/vt-go"
)

var APIkey = flag.String("apikey", "", "VirusTotal API key")
var fileSHA256 = flag.String("sha256", "", "SHA-256 of some file")

func main() {

    flag.Parse()
    client := vt.NewClient("<apikey>")

    file, err := client.GetObject(vt.URL("files/%s", sha256));
    if err != nil {
        log.Fatal(err)
    }

    ls, err := file.GetAttributeTime("last_submission_date");
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("File %s was submitted for the last time on %v", file.ID, ls)
}
```
