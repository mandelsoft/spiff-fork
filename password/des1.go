package password

import (
	"fmt"
)

type des1 struct {
}

func (e des1) Name() string {
	return TRIPPLEDES
}

func (e des1) Encode(text string, key string) (string, error) {
	c, err := GetCipher(key)
	if err != nil {
		return "", err
	}
	r := EncodeString(text, c)
	return r, nil
}

func (e des1) Decode(text string, key string) (string, error) {
	c, err := GetCipher(key)
	if err != nil {
		return "", err
	}
	r := DecodeString(text, c)
	if r == "" {
		return "", fmt.Errorf("invalid key")
	}
	return r, nil
}
