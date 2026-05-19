package health

import (
	"os"
	"path/filepath"
	"strings"
)

func PathState(path string, directory bool) string {
	if strings.TrimSpace(path) == "" {
		return "missing_path"
	}
	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return "missing"
		}
		return "error"
	}
	if directory && !info.IsDir() {
		return "not_directory"
	}
	if !directory && info.IsDir() {
		return "not_file"
	}
	return "ok"
}
