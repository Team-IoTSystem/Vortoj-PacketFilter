package utility

import (
	"os"
)

// file existance check
// is file exist to true
func Exists(name string) bool {
	_, err := os.Stat(name)
	return !os.IsNotExist(err)
}
