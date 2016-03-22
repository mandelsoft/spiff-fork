package password

import (
	"C"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"syscall"

	"encoding/base64"
	"strings"

	"github.com/cloudfoundry-incubator/candiedyaml"
	"github.com/cloudfoundry-incubator/spiff/debug"
	"github.com/cloudfoundry-incubator/spiff/yaml"
)

const (
	KEYS       = "keys"
	ENCRYPTED  = "encrypted"
	ENCODING   = "encoding"
	TRIPPLEDES = "3DES"

	SECRET   = "spiff is a cool tool"
	REDACTED = "<redacted>"
)

type Encoding interface {
	Encode(text string, key string) (string, error)
	Decode(text string, key string) (string, error)
	Name() string
}

var encodings = map[string]Encoding{
	TRIPPLEDES: des1{},
}

type PasswordFile struct {
	path     string
	raw      yaml.Node
	node     map[string]yaml.Node
	key      string
	encoding Encoding
	fd       int
}

var files = map[string]*PasswordFile{}

func GetEncoding(name string) (Encoding, bool) {
	e, ok := encodings[name]
	return e, ok
}

func GetPasswordFile(path string, key string) (*PasswordFile, error) {
	debug.Debug("setup passwords in %s", path)
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0660)
	if err != nil {
		return nil, err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}

	var raw yaml.Node
	p := files[path]
	if p == nil {
		debug.Debug("lock passwords in %s", path)
		err = syscall.Flock(fd, syscall.LOCK_EX)
		if err != nil {
			return nil, err
		}
		debug.Debug("read passwords in %s", path)
		passwordFile, err := ioutil.ReadFile(path)
		if err != nil {
			raw = yaml.NewNode(map[string]yaml.Node{}, path)
		} else {
			raw, err = yaml.Parse(path, passwordFile)
		}

		p = &PasswordFile{path: path, raw: raw, fd: fd, key: key}
		debug.Debug("create encoding")
		encoding := ""
		n, ok := raw.Value().(map[string]yaml.Node)
		if ok {
			s, ok := n[ENCODING]
			if ok {
				encoding, ok = s.Value().(string)
				if !ok {
					err = fmt.Errorf("encoding must be a string value")
				}
			} else {
				encoding = TRIPPLEDES
			}
		} else {
			err = fmt.Errorf("invalid password file structure")
		}
		if err == nil {
			p.encoding, ok = encodings[encoding]
			if ok {
				err = decrypt(p)
			} else {
				err = fmt.Errorf("unknown encoding '%s'", encoding)
			}
		}
		if err != nil {
			syscall.Flock(fd, syscall.LOCK_UN)
			syscall.Close(fd)
			return nil, err
		}
		files[path] = p
	} else {
		syscall.Close(fd)
		debug.Debug("reusing %s\n", path)
	}

	if p.key != key {
		return nil, fmt.Errorf("non-matching key")
	}
	return p, err
}

func GetPassword(tag string, path string, key string) (string, error) {
	p, err := GetPasswordFile(path, key)
	if err != nil {
		return "", err
	}

	debug.Debug("password file %p\n", p)
	v, ok := p.node[tag]
	if !ok {
		debug.Debug("no entry for password key %s\n", tag)
		buf := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			panic(err)
		}

		randomKey := base64.StdEncoding.EncodeToString(buf)
		v = yaml.NewNode(randomKey, p.path)
		p.node[tag] = v
		SavePasswordFile(p)
	}
	return v.Value().(string), nil
}

func compact(text string) string {
	return strings.Replace(text, "\n", "", -1)
}
func split(text string) string {
	result := ""
	max := 64
	for len(text) > max {
		result += text[:max] + "\n"
		text = text[max:]
	}
	return result + text
}

func decrypt(p *PasswordFile) error {
	if p.raw == nil {
		p.node = map[string]yaml.Node{}
		return nil
	}
	m, ok := p.raw.Value().(map[string]yaml.Node)
	if !ok {
		return fmt.Errorf("%s is no valid password file", p.path)
	}

	e, ok := m[ENCRYPTED]
	if ok {
		encoded, ok := e.Value().(string)
		if ok {
			text, err := p.encoding.Decode(compact(encoded), p.key)
			if err != nil {
				return err
			}
			//fmt.Printf("found: %s\n",text)
			n, err := yaml.Parse(p.path, []byte(text))
			if err != nil {
				return fmt.Errorf("%s: invalid passphrase?", err)
			}
			p.node = n.Value().(map[string]yaml.Node)
			keysNode, ok := p.raw.Value().(map[string]yaml.Node)[KEYS]
			if !ok {
				keysNode = yaml.NewNode(map[string]yaml.Node{}, p.path)
			}
			modified := false
			keys := keysNode.Value().(map[string]yaml.Node)

			for k, _ := range p.node {
				if _, ok := keys[k]; !ok {
					debug.Debug("  delete key %s\n", k)
					delete(p.node, k)
					modified = true
				}
			}

			for k, v := range keys {
				if s, ok := v.Value().(string); ok && s != REDACTED && s != "" {
					debug.Debug("  set key %s to %s\n", k, s)
					p.node[k] = yaml.NewNode(s, p.path)
					modified = true
				}
			}

			p.raw = nil
			if modified {
				SavePasswordFile(p)
			}
		} else {
			p.node = map[string]yaml.Node{}
		}
	} else {
		p.node = map[string]yaml.Node{}
	}
	return nil
}

func SavePasswordFile(p *PasswordFile) {
	debug.Debug("saving %s\n", p.path)
	out, err := candiedyaml.Marshal(yaml.NewNode(p.node, p.path))
	if err != nil {
		log.Fatalln("error marshalling manifest:", err)
	}

	encoded, err := p.encoding.Encode(string(out), p.key)
	if err != nil {
		log.Fatalln("error encrypting passwords:", err)
	}
	raw := map[string]yaml.Node{}
	raw[ENCRYPTED] = yaml.NewNode(split(encoded), p.path)
	raw[ENCODING] = yaml.NewNode(p.encoding.Name(), p.path)
	keys := map[string]yaml.Node{}
	set := yaml.NewNode(REDACTED, p.path)
	for k, _ := range p.node {
		keys[k] = set
	}
	raw[KEYS] = yaml.NewNode(keys, p.path)
	out, err = candiedyaml.Marshal(raw)
	ioutil.WriteFile(p.path, out, 0660)
}
