package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var userCache = make(map[uint32]string)
var groupCache = make(map[uint32]string)
var excludeDirs []string

func escapeCSV(s string) string {
    return strings.ReplaceAll(s, `"`, `""`)
}

func loadConfig(path string) {
    f, err := os.Open(path)
    if err != nil {
        fmt.Fprintf(os.Stderr, "cannot open config: %v\n", err)
        return
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if strings.HasPrefix(line, "get_metadatatime_exclude=") {
            start := strings.Index(line, "[")
            end := strings.LastIndex(line, "]")
            if start != -1 && end != -1 && end > start {
                raw := line[start+1 : end]
                parts := strings.Split(raw, ",")
                for _, p := range parts {
                    p = strings.Trim(p, ` "'`)
                    if p != "" {
                        excludeDirs = append(excludeDirs, p)
                    }
                }
            }
        }
    }
}

func fileTypeRune(mode os.FileMode) string {
	switch mode & os.ModeType {
	case os.ModeDir:
		return "d"
	case os.ModeSymlink:
		return "l"
	case os.ModeNamedPipe:
		return "p"
	case os.ModeSocket:
		return "s"
	case os.ModeDevice:
		if mode&os.ModeCharDevice != 0 {
			return "c"
		}
		return "b"
	default:
		return "-"
	}
}

func getUser(uid uint32) string {
	if name, ok := userCache[uid]; ok {
		return name
	}
	u, err := user.LookupId(fmt.Sprint(uid))
	if err != nil {
		userCache[uid] = "?"
		return "?"
	}
	userCache[uid] = u.Username
	return u.Username
}

func getGroup(gid uint32) string {
	if name, ok := groupCache[gid]; ok {
		return name
	}
	g, err := user.LookupGroupId(fmt.Sprint(gid))
	if err != nil {
		groupCache[gid] = "?"
		return "?"
	}
	groupCache[gid] = g.Name
	return g.Name
}

func formatTime(ts syscall.Timespec) string {
	return time.Unix(int64(ts.Sec), 0).Format("2006-01-02 15:04:05")
}


func main() {
	execPath, _ := os.Executable()
	baseDir := filepath.Dir(filepath.Dir(execPath))
	configPath := filepath.Join(baseDir, "CLLF.config")

	loadConfig(configPath)

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	fmt.Fprintln(w, "Permission,uOwner,gOwner,Size,Parent Path,File Path,File Extension,Create Time,Access Time,Modify Time")

	filepath.WalkDir("/", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		for _, ex := range excludeDirs {
			if strings.HasPrefix(path, ex) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		stat := info.Sys().(*syscall.Stat_t)

		fType := fileTypeRune(info.Mode())
		perm := fmt.Sprintf("%s%#o", fType, stat.Mode&0777)

		uOwner := getUser(stat.Uid)
		gOwner := getGroup(stat.Gid)
		size := info.Size()

		dir := filepath.Dir(path) + "/"
		ext := filepath.Ext(info.Name())

		ctime := formatTime(stat.Ctim)
		atime := formatTime(stat.Atim)
		mtime := formatTime(stat.Mtim)

		// fmt.Fprintf(w, "%s,%s,%s,%d,%s,%s,%s,%s,%s,%s\n",
		// 	perm, uOwner, gOwner, size, dir, path, ext, ctime, atime, mtime)
			
		fmt.Fprintf(w, "%s,%s,%s,%d,\"%s\",\"%s\",\"%s\",%s,%s,%s\n",
			perm, uOwner, gOwner, size, escapeCSV(dir), escapeCSV(path), escapeCSV(ext), ctime, atime, mtime)

		return nil
	})
}