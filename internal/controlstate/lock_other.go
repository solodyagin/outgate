//go:build !linux && !windows

package controlstate

import "os"

func lockOwner(*os.File) error { return ErrUnavailable }
