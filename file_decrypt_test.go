package l2cryptor

import (
	"os"
	"path/filepath"
	"testing"
)

var key413 rsaKey

func init() {
	key413.
		setN("97df398472ddf737ef0a0cd17e8d172f0fef1661a38a8ae1d6e829bc1c6e4c3cfc19292dda9ef90175e46e7394a18850b6417d03be6eea274d3ed1dde5b5d7bde72cc0a0b71d03608655633881793a02c9a67d9ef2b45eb7c08d4be329083ce450e68f7867b6749314d40511d09bc5744551baa86a89dc38123dc1668fd72d83").
		setD("35")
}

func TestDecryptDatFiles(t *testing.T) {
	filter := []string{".dat"}

	os.Chdir("original_files")
	defer os.Chdir("..")

	entries, _ := os.ReadDir(".")

	for _, entry := range entries {
		for _, f := range filter {
			if f != filepath.Ext(entry.Name()) {
				continue
			}
		}

		if err := DecryptFile(entry.Name(), &key413, ""); err != nil {
			t.Log(err)
		}

		out := "dec." + entry.Name()
		if _, err := os.Stat(out); os.IsNotExist(err) {
			t.Error(out, "not found!")
		} else {
			os.Remove(out)
		}
	}
}
