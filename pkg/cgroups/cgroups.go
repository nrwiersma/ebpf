// +build linux

package cgroups

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const DefaultCgroupRoot = "/var/run/ebpf/cgroupv2"

var (
	cgroupRoot = DefaultCgroupRoot
)

// CgroupRoot returns the path of the cgroupv2 mount.
func CgroupRoot() string {
	return cgroupRoot
}

func EnsureCgroupFS(path string) error {
	if path == "" {
		path = DefaultCgroupRoot
	}

	mounted, isCgroup, err := isMountFS(cgroupRoot, unix.CGROUP2_SUPER_MAGIC)
	if err != nil {
		return fmt.Errorf("unable to determine mount status: %w", err)
	}

	if !mounted {
		return mountCgroup(path)
	}

	if !isCgroup {
		return fmt.Errorf("mount path %q is not a cgroupv2 filesystem", path)
	}

	cgroupRoot = path
	return nil
}

func mountCgroup(path string) error {
	stat, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("unable to stat the mount path %s: %w", path, err)
		}

		if err = os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("unable to create cgroup mount directory: %s", err)
		}
	} else if !stat.IsDir() {
		return fmt.Errorf("unable to mount %q as it is not a directory", path)
	}

	if err = unix.Mount("none", path, "cgroup2", 0, ""); err != nil {
		return fmt.Errorf("unable to mount %s: %s", path, err)
	}
	return nil
}

func isMountFS(path string, mntType int64) (bool, bool, error) {
	var st unix.Stat_t
	err := unix.Lstat(path, &st)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			// non-existent path can't be a mount point
			return false, false, nil
		}
		return false, false, &os.PathError{Op: "lstat", Path: path, Err: err}
	}

	var pst unix.Stat_t
	parent := filepath.Dir(path)
	err = unix.Lstat(parent, &pst)
	if err != nil {
		return false, false, &os.PathError{Op: "lstat", Path: parent, Err: err}
	}
	if st.Dev == pst.Dev {
		// parent has the same dev -- not a mount point
		return false, false, nil
	}

	// Check the fstype
	var fst unix.Statfs_t
	err = unix.Statfs(path, &fst)
	if err != nil {
		return true, false, &os.PathError{Op: "statfs", Path: path, Err: err}
	}

	return true, fst.Type == mntType, nil
}
