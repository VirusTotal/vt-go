package vt

func PostCollectionFromRawText(client *Client, name, text string) (*Object, error) {
	obj := NewObject("collection")
	obj.setMeta("raw", text)
	if err := obj.SetString("name", name); err != nil {
		return obj, err
	}
	err := client.PostObject(URL("/collections"), obj)
	return obj, err
}
