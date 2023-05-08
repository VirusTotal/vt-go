package mock

import (
	"io"
	"net/url"

	"github.com/VirusTotal/vt-go"
	"github.com/stretchr/testify/mock"
)

type Client struct {
	mock.Mock
}

func (c *Client) Get(url *url.URL, options ...vt.RequestOption) (*vt.Response, error) {
	args := c.Called(url, options)
	return args.Get(0).(*vt.Response), args.Error(1)
}

func (c *Client) Post(url *url.URL, req *vt.Request, options ...vt.RequestOption) (*vt.Response, error) {
	args := c.Called(url, req, options)
	return args.Get(0).(*vt.Response), args.Error(1)
}

func (c *Client) Patch(url *url.URL, req *vt.Request, options ...vt.RequestOption) (*vt.Response, error) {
	args := c.Called(url, req, options)
	return args.Get(0).(*vt.Response), args.Error(1)
}

func (c *Client) Delete(url *url.URL, options ...vt.RequestOption) (*vt.Response, error) {
	args := c.Called(url, options)
	return args.Get(0).(*vt.Response), args.Error(1)
}

func (c *Client) GetData(url *url.URL, target interface{}, options ...vt.RequestOption) (*vt.Response, error) {
	args := c.Called(url, target, options)
	return args.Get(0).(*vt.Response), args.Error(1)
}

func (c *Client) PostData(url *url.URL, data interface{}, options ...vt.RequestOption) (*vt.Response, error) {
	args := c.Called(url, data, options)
	return args.Get(0).(*vt.Response), args.Error(1)
}

func (c *Client) DeleteData(url *url.URL, data interface{}, options ...vt.RequestOption) (*vt.Response, error) {
	args := c.Called(url, data, options)
	return args.Get(0).(*vt.Response), args.Error(1)
}

func (c *Client) PostObject(url *url.URL, obj *vt.Object, options ...vt.RequestOption) error {
	args := c.Called(url, obj, options)
	return args.Error(0)
}

func (c *Client) GetObject(url *url.URL, options ...vt.RequestOption) (*vt.Object, error) {
	args := c.Called(url, options)
	return args.Get(0).(*vt.Object), args.Error(1)
}

func (c *Client) PatchObject(url *url.URL, obj *vt.Object, options ...vt.RequestOption) error {
	args := c.Called(url, obj, options)
	return args.Error(0)
}

func (c *Client) DownloadFile(hash string, w io.Writer) (int64, error) {
	args := c.Called(hash, w)
	return args.Get(0).(int64), args.Error(1)
}

func (c *Client) Iterator(url *url.URL, options ...vt.IteratorOption) (*vt.Iterator, error) {
	args := c.Called(url, options)
	return args.Get(0).(*vt.Iterator), args.Error(1)
}

func (c *Client) Search(query string, options ...vt.IteratorOption) (*vt.Iterator, error) {
	args := c.Called(query, options)
	return args.Get(0).(*vt.Iterator), args.Error(1)
}

func (c *Client) GetMetadata() (*vt.Metadata, error) {
	args := c.Called()
	return args.Get(0).(*vt.Metadata), args.Error(1)
}

func (c *Client) NewFileScanner() *vt.FileScanner {
	args := c.Called()
	return args.Get(0).(*vt.FileScanner)
}

func (c *Client) NewURLScanner() *vt.URLScanner {
	args := c.Called()
	return args.Get(0).(*vt.URLScanner)
}

func (c *Client) NewMonitorUploader() *vt.MonitorUploader {
	args := c.Called()
	return args.Get(0).(*vt.MonitorUploader)
}
