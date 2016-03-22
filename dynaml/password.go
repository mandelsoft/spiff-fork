package dynaml

import (
	"os"

	"github.com/cloudfoundry-incubator/spiff/password"
)

func func_decrypt(arguments []interface{}, binding Binding) (interface{}, EvaluationInfo, bool) {
	info := DefaultInfo()

	if len(arguments) < 1 || len(arguments) > 3 {
		return info.Error("decrypt takes one to three arguments")
	}

	text, ok := arguments[0].(string)
	if !ok {
		return info.Error("first (text) argument of decrypt must be a string")
	}
	passphrase := ""
	if len(arguments) > 1 {
		passphrase, ok = arguments[len(arguments)-1].(string)
		if !ok {
			return info.Error("passphrase argument of decrypt must be a string")
		}
	} else {
		passphrase = os.Getenv("SPIFF_PASSPHRASE")
	}
	if passphrase == "" {
		return info.Error("missing or empty passphrase")
	}
	encoding := password.TRIPPLEDES
	if len(arguments) > 2 {
		encoding, ok = arguments[1].(string)
		if !ok || encoding == "" {
			return info.Error("encoding argument of decrypt must be a non-empty string")
		}
	}

	e, ok := password.GetEncoding(encoding)
	if !ok {
		return info.Error("invalid encoding '%s'", encoding)
	}
	r, err := e.Decode(text, passphrase)
	if err != nil {
		return info.Error("%s", err)
	}
	return r, info, true
}

func func_password(arguments []interface{}, binding Binding) (interface{}, EvaluationInfo, bool) {
	info := DefaultInfo()

	if len(arguments) < 2 || len(arguments) > 3 {
		return info.Error("password takes two or three arguments")
	}

	tag, ok := arguments[0].(string)
	if !ok {
		return info.Error("string expected for password tag")
	}

	path, ok := arguments[1].(string)
	if !ok {
		return info.Error("string expected for password file path")
	}

	var key string
	if len(arguments) == 3 {
		key, ok = arguments[2].(string)
		if !ok {
			return info.Error("string expected for pass phrase")
		}
	} else {
		key = os.Getenv("SPIFF_PASSPHRASE")
	}

	if key == "" {
		return info.Error("passphrase required for password file")
	}

	pass, err := password.GetPassword(tag, path, key)
	if err != nil {
		return info.Error("%s", err)
	}

	return pass, info, true
}
