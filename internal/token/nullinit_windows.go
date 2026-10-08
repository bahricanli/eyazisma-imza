//go:build windows

package token

import "syscall"

// initializeWithoutArguments starts a driver the way some of them insist on:
// with no arguments at all. It returns the driver's return value.
func initializeWithoutArguments(path string) uint {
	library, err := syscall.LoadDLL(path)
	if err != nil {
		return 0xFFFFFFFF
	}

	initialize, err := library.FindProc("C_Initialize")
	if err != nil {
		return 0xFFFFFFFE
	}

	result, _, _ := initialize.Call(0)

	return uint(result)
}
