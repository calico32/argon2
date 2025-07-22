package argon2_test

import (
	"fmt"

	"github.com/calico32/argon2"
)

func ExampleHash() {
	hash := argon2.Hash([]byte("examplepassword"))
	// save hash to database or use it as needed

	// later:
	// get password from user to verify
	password := []byte("examplepassword")
	if !argon2.Verify(hash, password) {
		// verification failed
		fmt.Println("Incorrect username or password")
		return
	}

	// verification succeeded
	fmt.Println("Welcome back!")
}
