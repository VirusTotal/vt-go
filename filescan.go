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

package vt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/url"
	"os"
	"strings"
)

type progressReader struct {
	reader     io.Reader
	total      int64
	read       int64
	progressCh chan<- float32
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.read += int64(n)
	if pr.progressCh != nil {
		pr.progressCh <- float32(pr.read) / float32(pr.total) * 100
	}
	return n, err
}

// FileScanner represents a file scanner.
type FileScanner struct {
	cli *Client
}

func (s *FileScanner) scanWithParameters(
	r io.Reader, filename string, progress chan<- float32, parameters map[string]string) (*Object, error) {

	// File size is initially unknown.
	fileSize := int64(-1)

	// Try to determine the size of the file being uploaded.
	switch v := r.(type) {
	case *os.File:
		if stat, err := v.Stat(); err == nil {
			fileSize = stat.Size()
		}
	case *bytes.Buffer:
		fileSize = int64(v.Len())
	case *bytes.Reader:
		fileSize = int64(v.Len())
	case *strings.Reader:
		fileSize = int64(v.Len())
	default:
	}

	// If the size was not determined by other means, read the entire
	// content into a buffer to determine the size.
	if fileSize == -1 {
		b := bytes.Buffer{}
		io.Copy(&b, r)
		fileSize = int64(b.Len())
		r = &b
	}

	pipeReader, pipeWriter := io.Pipe()
	multipartWriter := multipart.NewWriter(pipeWriter)

	// Read data from the input reader `r`, and write it into the multipart
	// writer in a separate goroutine using a pipe. Data is read from `r`
	// only as requested by the HTTP client to avoid loading all the data
	// into memory.
	go func() {
		defer pipeWriter.Close()
		defer multipartWriter.Close()

		f, err := multipartWriter.CreateFormFile("file", filename)
		if err != nil {
			pipeWriter.CloseWithError(err)
			return
		}

		if _, err := io.Copy(f, r); err != nil {
			pipeWriter.CloseWithError(err)
			return
		}

		for key, val := range parameters {
			if err := multipartWriter.WriteField(key, val); err != nil {
				pipeWriter.CloseWithError(err)
				return
			}
		}
	}()

	var uploadURL *url.URL
	var err error

	// Choose upload URL based on the file size. If the size is known and less
	// than maxPayloadSize, we can upload directly to /files. If the size is
	// unknown or larger than maxPayloadSize, we need to request an upload URL
	// first. If the size is larger than maxFileSize, we return an error.
	if fileSize > maxFileSize {
		return nil, fmt.Errorf("file size can't be larger than %d bytes", maxFileSize)
	} else if fileSize > maxPayloadSize {
		var u string
		if _, err = s.cli.GetData(URL("files/upload_url"), &u); err != nil {
			return nil, err
		}
		if uploadURL, err = url.Parse(u); err != nil {
			return nil, err
		}
	} else {
		uploadURL = URL("files")
	}

	progressReader := &progressReader{
		reader:     pipeReader,
		total:      fileSize,
		progressCh: progress}

	headers := map[string]string{"Content-Type": multipartWriter.FormDataContentType()}

	httpResp, err := s.cli.sendRequest("POST", uploadURL, progressReader, headers)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	apiResp, err := s.cli.parseResponse(httpResp)
	if err != nil {
		return nil, err
	}

	analysis := &Object{}
	if err := json.Unmarshal(apiResp.Data, analysis); err != nil {
		return nil, err
	}

	return analysis, nil
}

// ScanParameters sends a file to VirusTotal for scanning. The file content is
// read from the r io.Reader and sent to VirusTotal with the provided file name
// which can be left blank. The function also sends a float32 through the
// progress channel indicating the percentage of the file that has been already
// uploaded. The progress channel can be nil if the caller is not interested in
// receiving upload progress updates. An analysis object is returned as soon as
// the file is uploaded. Additional parameters can be passed to the scan
// by using the parameters map[string]string argument.
func (s *FileScanner) ScanParameters(
	r io.Reader, filename string, progress chan<- float32, parameters map[string]string) (*Object, error) {
	return s.scanWithParameters(r, filename, progress, parameters)
}

// ScanFileWithParameters sends a file to VirusTotal for scanning. This function
// is similar to ScanWithParameters but it receives an *os.File instead of a
// io.Reader and a file name.
func (s *FileScanner) ScanFileWithParameters(
	f *os.File, progress chan<- float32, parameters map[string]string) (*Object, error) {
	return s.scanWithParameters(f, f.Name(), progress, parameters)
}

// Scan sends a file to VirusTotal for scanning. The file content is read from
// the r io.Reader and sent to VirusTotal with the provided file name which can
// be left blank. The function also sends a float32 through the progress channel
// indicating the percentage of the file that has been already uploaded. The
// progress channel can be nil if the caller is not interested in receiving
// upload progress updates. An analysis object is returned as soon as the file
// is uploaded.
func (s *FileScanner) Scan(r io.Reader, filename string, progress chan<- float32) (*Object, error) {
	return s.scanWithParameters(r, filename, progress, nil)
}

// ScanFile sends a file to VirusTotal for scanning. This function is similar to
// Scan but it receive an *os.File instead of a io.Reader and a file name.
func (s *FileScanner) ScanFile(f *os.File, progress chan<- float32) (*Object, error) {
	return s.Scan(f, f.Name(), progress)
}
