package main

import (
	"bufio"
	stdflag "flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/calico32/argon2"
	"golang.org/x/term"
	"rsc.io/getopt"
)

var flag = getopt.NewFlagSet("argon2", stdflag.ExitOnError)
var mFlag = flag.Uint("memory", 65536, "memory in KB")
var tFlag = flag.Uint("iterations", 1, "number of iterations")
var pFlag = flag.Uint("parallelism", 1, "parallelism")
var kFlag = flag.Uint("key-length", 32, "key length in bytes")
var sFlag = flag.Uint("salt-length", 16, "salt length in bytes")
var stdinFlag = flag.Bool("stdin", false, "read input from stdin")
var helpFlag = flag.Bool("help", false, "display help")

func init() {
	flag.Alias("m", "memory")
	flag.Alias("t", "iterations")
	flag.Alias("p", "parallelism")
	flag.Alias("k", "key-length")
	flag.Alias("s", "salt-length")
	flag.Alias("S", "stdin")
	flag.Alias("h", "help")
	flag.Usage = func() {
		w := func(format string, args ...any) {
			fmt.Fprintf(flag.Output(), format, args...)
		}
		w("Usage of %s:\n", flag.Name())
		w("  %s help\t\t\t\t\tdisplay this help\n", flag.Name())
		w("  %s [options]\t\t\t\thash a password\n", flag.Name())
		w("  %s [options] hash [password]\t\thash a password\n", flag.Name())
		w("  %s [options] verify [hash] [password]\tverify a password\n", flag.Name())
		w("\n")
		w("When omitted, arguments are prompted for or read from stdin\n")
		w("using the -S/--stdin. Note that providing either the hash or\n")
		w("password to verify via stdin disables interactive prompting\n")
		w("for the other.\n")
		w("\n")
		w("When verifying a hash, -m, -t, -p, -k, and -s are set by the\n")
		w("hash and ignored.\n")
		w("\n")
		w("Take care to escape or quote passwords and hashes containing\n")
		w("special characters, such as '$', to prevent the shell from\n")
		w("interpreting them.\n")
		w("\n")
		w("Options:\n")
		flag.PrintDefaults()
		w("\n")
		w("Examples:\n")
		w("  %s\n", flag.Name())
		w("      prompts for a password and hashes it using default parameters\n")
		w("  %s hash mypassword\n", flag.Name())
		w("      hashes 'mypassword' using default parameters\n")
		w("  %s -m 47106 -t 3 -p 2 hash mypassword\n", flag.Name())
		w("      hashes 'mypassword' using 47106 KB memory, 3 iterations, and\n")
		w("      2 parallel threads\n")
		w("  %s -S verify '$argon2id$v=19$m=65536,t=3,p=2$eW91ciBzYWx0$ZGF0YQ=='\n", flag.Name())
		w("      verifies a password from stdin against the given hash\n")
	}
}

func main() {
	err := flag.Parse(os.Args[1:])
	if err != nil {
		os.Exit(1)
	}
	if *helpFlag {
		flag.Usage()
		os.Exit(0)
	}
	command := flag.Arg(0)
	switch command {
	case "help":
		flag.Usage()
	case "":
		hash(flag.Args())
	case "hash":
		hash(flag.Args()[1:])
	case "verify":
		verify(flag.Args()[1:])
	default:
		fmt.Fprintf(flag.Output(), "Unknown command: %s\n", command)
		fmt.Fprintf(flag.Output(), "Use '%s help' for usage information.\n", flag.Name())
	}
}

func hash(args []string) {
	var password string
	if len(args) == 1 {
		password = args[0]
	} else if *stdinFlag {
		var err error
		password, err = readStdin()
		if err != nil {
			fmt.Printf("Error reading from stdin: %v\n", err)
			os.Exit(1)
		}
	} else {
		password = promptPassword("Enter password: ")
	}

	if len(password) == 0 {
		fmt.Printf("Password cannot be empty.\n")
		os.Exit(1)
	}

	h := argon2.NewHash(
		uint32(*tFlag),
		uint32(*mFlag),
		uint8(*pFlag),
		uint32(*sFlag),
		uint32(*kFlag))

	hash := h.Hash([]byte(password))
	fmt.Printf("%s\n", hash)
}

func verify(args []string) {
	var password string
	var hash string
	if len(args) == 2 {
		hash = args[0]
		password = args[1]
	} else if *stdinFlag {
		// password or hash from stdin
		stdin, err := readStdin()
		if err != nil {
			fmt.Printf("Error reading from stdin: %v\n", err)
			os.Exit(1)
		}
		// try to parse as hash
		_, _, _, err = argon2.Parse([]byte(stdin))
		if err == nil {
			// stdin is a hash
			hash = stdin
			// find password in args
			if len(args) == 1 {
				password = args[0]
			} else {
				fmt.Printf("No password provided.\n")
				fmt.Printf("Usage: %s -S verify <password> (hash via stdin)\n", flag.Name())
				os.Exit(1)
			}
		} else {
			// stdin probably contains a password
			password = stdin
			// find hash in args
			if len(args) == 1 {
				hash = args[0]
			} else {
				fmt.Printf("No hash provided.\n")
				fmt.Printf("Usage: %s -S verify <hash> (password via stdin)\n", flag.Name())
				os.Exit(1)
			}
		}
	} else if len(args) == 1 {
		// try to parse as hash
		_, _, _, err := argon2.Parse([]byte(args[0]))
		if err == nil {
			// args[0] is a hash
			hash = args[0]
			password = promptPassword("Enter password: ")
		} else {
			// args[0] is probably a password
			password = args[0]
			hash = prompt("Enter hash: ")
		}
	} else {
		// prompt for both hash and password
		hash = prompt("Enter hash: ")
		password = promptPassword("Enter password: ")
	}

	if len(password) == 0 {
		fmt.Printf("Password cannot be empty.\n")
		os.Exit(1)
	}

	if len(hash) == 0 {
		fmt.Printf("Hash cannot be empty.\n")
		os.Exit(1)
	}

	// Parse the hash to ensure it's valid
	_, _, _, err := argon2.Parse([]byte(hash))
	if err != nil {
		fmt.Printf("Invalid hash: %v\n", err)
		os.Exit(1)
	}

	result := argon2.Verify([]byte(hash), []byte(password))
	if result {
		fmt.Println("Password matches the hash.")
	} else {
		fmt.Println("Password does not match the hash.")
	}
	os.Exit(0)
}

// readStdin reads all of stdin and returns it as a string, trimming any leading
// or trailing whitespace. It returns an error if reading from stdin fails.
func readStdin() (string, error) {
	s, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(s)), nil
}

// prompt displays a prompt and reads a line of input from the user, trimming
// any leading or trailing whitespace.
func prompt(prompt string) string {
	fmt.Printf("%s", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _, err := reader.ReadLine()
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(line))
}

// promptPassword disables input echoing, reads a line of input from the user,
// and returns it as a string. It does not trim whitespace, as passwords
// may contain leading or trailing spaces that are significant.
func promptPassword(prompt string) string {
	fmt.Printf("%s", prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}
	fmt.Println() // Print a newline after the password input
	return string(password)
}
