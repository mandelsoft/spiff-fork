package password

import (
	"C"
	"crypto/rand"
	"io"

	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
)

func GetCipher(key string) (cipher.Block, error) {
	hash := md5.New()
	k := hash.Sum([]byte(key))
	var tripleDESKey []byte
	tripleDESKey = append(tripleDESKey, k[:16]...)
	tripleDESKey = append(tripleDESKey, k[:8]...)

	return des.NewTripleDESCipher(tripleDESKey)
}

func DecodeString(text string, c cipher.Block) string {

	ciphertext, _ := hex.DecodeString(text)

	if len(ciphertext) < c.BlockSize() {
		panic("ciphertext too short")
	}
	iv := ciphertext[:c.BlockSize()]
	ciphertext = ciphertext[c.BlockSize():]

	if len(ciphertext)%c.BlockSize() != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(c, iv)

	mode.CryptBlocks(ciphertext, ciphertext)

	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2.
	pad := int(ciphertext[len(ciphertext)-1] + 1)
	m := len(ciphertext) - pad
	l := m - sha256.Size

	//fmt.Printf("len: %d, pad: %d, eff: %d\n",len(ciphertext),int(ciphertext[len(ciphertext)-1]),l)
	if m > len(ciphertext) || m <= 0 || l <= 0 || pad < 1 {
		return ""
	}

	message := ciphertext[:l]
	if !CheckMAC(message, ciphertext[l:m], []byte(SECRET)) {
		return ""
	}
	return string(message)
}

func EncodeString(text string, c cipher.Block) string {
	return Encode([]byte(text), c)
}

func Encode(plaintext []byte, c cipher.Block) string {
	l := len(plaintext)
	mac := MAC(plaintext, []byte(SECRET))
	// fmt.Printf("mac size %d\n", sha256.Size)
	m := l + sha256.Size
	pad := (c.BlockSize() - (m+1)%c.BlockSize()) % c.BlockSize()

	//fmt.Printf("len: %d, pad: %d\n",l,pad)

	// see https://tools.ietf.org/html/rfc5246#section-6.2.3.2.
	if (l+pad+1)%c.BlockSize() != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	ciphertext := make([]byte, c.BlockSize()+m+pad+1)
	iv := ciphertext[:c.BlockSize()]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	copy(ciphertext[c.BlockSize():], plaintext)
	copy(ciphertext[c.BlockSize()+l:], mac)
	for i := 0; i <= pad; i++ {
		ciphertext[c.BlockSize()+m+i] = byte(pad)
	}

	mode := cipher.NewCBCEncrypter(c, iv)
	mode.CryptBlocks(ciphertext[c.BlockSize():], ciphertext[c.BlockSize():])

	return hex.EncodeToString(ciphertext)
}

func MAC(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func CheckMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
