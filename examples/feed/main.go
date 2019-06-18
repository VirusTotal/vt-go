// Copyright © 2017 The vt-go authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This test program exemplifies the use of vt-go for retrieving the file
// feed from VirusTotal. For using this program you need an API key with
// privileges for accessing the feed API.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/VirusTotal/vt-go"
)

// Command-line arguments accepted by the program.
var apikey = flag.String("apikey", "", "VirusTotal API key")
var bufferSize = flag.Int("buffer-size", 100, "buffer size")
var cursor = flag.String("cursor", "", "continuation cursor")

func main() {
	flag.Parse()

	vt.SetHost("devel-dot-core-dot-virustotalcloud.appspot.com")

	client := vt.NewClient(*apikey)

	feed, err := client.NewFeed(vt.FileFeed,
		vt.FeedBufferSize(*bufferSize),
		vt.FeedCursor(*cursor))

	if err != nil {
		fmt.Printf("error: %+v", err)
		return
	}

	// Capture SIGINT and SIGTERM signals and stop the program gracefully.
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		feed.Stop()
	}()

	// Get files from the feed until the program is stopped. You can use
	// Ctrl+C for stopping it.
	for obj := range feed.C {
		fmt.Println(obj.ID)
	}

	fmt.Printf("\nFor continuing where you left use option: --cursor %s\n", feed.Cursor())
}
