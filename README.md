[![GoDoc](https://godoc.org/github.com/VirusTotal/vt-go?status.svg)](https://godoc.org/github.com/VirusTotal/vt-go)

# vt-go

This is the official Go client library for VirusTotal. With this library you can
interact with the VirusTotal REST API v3 without having to send plain HTTP requests
with the standard "http" package.

## Quick example

```golang

import (
    "fmt"
    "log"
	vt "github.com/VirusTotal/vt-go"
)

func main() {
    client := vt.NewClient("<apikey>")

    if file, err := client.GetObject(vt.URL("file/%s", sha256)); err != nil {
        log.Fatal(err)
    }

    if ls, err := file.GetAttributeTime("last_submission_date"); err == nil {
        fmt.Printf("File %s was submitted for the last time on %v", file.ID, ls)
    }
    else {
        log.Fatal(err)
    }
}
```
