package vt

type CollectionBuilder struct {
	client  *Client
	rawText string
}

func NewCollectionBuilder(client *Client) *CollectionBuilder {
	c := &CollectionBuilder{
		client: client,
	}
	return c
}

func (c *CollectionBuilder) AddRawText(text string) {
	if c.rawText == "" {
		c.rawText = text
	} else {
		c.rawText += " " + text
	}
}

func (c *CollectionBuilder) PostCollection(name string) (*Object, error) {
	obj := NewObject("collection")
	obj.setMeta("raw", c.rawText)
	if err := obj.SetString("name", name); err != nil {
		return obj, err
	}
	err := c.client.PostObject(URL("/collections"), obj)
	return obj, err
}
