package main

import (
	"fmt"
)

// https://github.com/mfpierre/go-mcrypt/blob/master/README.md
func main() {

	value := "nl3G7UCCRRFKLj7jXP4PD/mZtapjrB+TG/en3ibvwc5xJ9iVsqcKpSHFCwTs"
	key := "REDACTED"
	fmt.Println(chacha20poly1305Decrypt(value, key))

	plaintext := "The quick brown fox jumps over the lazy dog. Ethan TEST"
	key = "REDACTED"

	enc, err := rijandel256Encrypt(plaintext, key)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println("encrypted value: ", enc)

	dec, err := rijandel256Decrypt(enc, key)
	if err != nil {
		fmt.Println(err.Error())
	}

	fmt.Println("decrypted value: ", dec)

	// rijandel 128 mode ECB (1)
}
