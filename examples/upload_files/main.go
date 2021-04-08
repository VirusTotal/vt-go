package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	vt "github.com/VirusTotal/vt-go"
)

type FileUploaderResult struct {
	object *vt.Object
	err    error
}

type FileUploader struct {
	id       int
	filename string
	scanner  *vt.FileScanner
	results  chan<- FileUploaderResult
}

// uploadAndScan uploads files to VirusTotal
func uploadAndScan(fileUploader FileUploader, wg *sync.WaitGroup) {
	defer wg.Done()
	f, err := os.Open(fileUploader.filename)
	if err != nil {
		fileUploader.results <- FileUploaderResult{nil, err}
	} else {
		defer f.Close()
		object, err := fileUploader.scanner.ScanFile(f, nil)
		fileUploader.results <- FileUploaderResult{object, err}
	}
}

// uploadFiles finds all files contained in a given directory
func uploadFiles(path string, results chan FileUploaderResult, scanner *vt.FileScanner) {
	var wg sync.WaitGroup

	id_file := 0
	fmt.Printf("Scanning: %s \n", path)
	filepath.Walk(path, func(filename string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileUploader := FileUploader{id_file, filename, scanner, results}
			fmt.Printf("Uploading: %s \n", filename)
			wg.Add(1)
			go uploadAndScan(fileUploader, &wg)
			id_file++
		}

		return nil
	})

	wg.Wait()
	close(results)
}

func main() {
	apikey := flag.String("apikey", "", "VT apikey")
	path := flag.String("path", "", "files directory")

	flag.Parse()

	if *apikey == "" || *path == "" {
		fmt.Println("ERROR: Apikey and Path are required")
		os.Exit(0)
	}

	client := vt.NewClient(*apikey)

	scanner := client.NewFileScanner()

	results := make(chan FileUploaderResult)

	go uploadFiles(*path, results, scanner)

	for result := range results {
		if result.err != nil {
			fmt.Println(result.err)
			continue
		} else {
			fmt.Printf("ID: %s Type: %s \n", result.object.ID(), result.object.Type())
			url := fmt.Sprintf("analyses/%s", result.object.ID())
			analysis, err := client.GetObject(vt.URL(url))
			if err != nil {
				log.Printf("Error: %v \n", err)
			} else {
				status, _ := analysis.Get("status")
				fmt.Printf("Analysis Status: %s \n", status)
			}
		}
	}

}
