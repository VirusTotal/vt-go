package vt_test

import (
	"fmt"

	vt "github.com/VirusTotal/vt-go"
)

func ExampleURL() {
	url := vt.URL("files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
	fmt.Println(url)

	url = vt.URL("intelligence/retrohunt_jobs/%s", "1234567")
	fmt.Println(url)
	// Output:
	// https://www.virustotal.com/api/v3/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
	// https://www.virustotal.com/api/v3/intelligence/retrohunt_jobs/1234567
}
