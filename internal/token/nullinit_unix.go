//go:build !windows

package token

/*
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>

typedef unsigned long (*initialize_function)(void *);

// Calls C_Initialize(NULL) of the driver. The library stays loaded, so the
// PKCS#11 wrapper that loads it next finds it initialised.
static unsigned long initialize_without_arguments(const char *path) {
	void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (library == NULL) {
		return 0xFFFFFFFFUL;
	}

	initialize_function initialize = (initialize_function) dlsym(library, "C_Initialize");
	if (initialize == NULL) {
		return 0xFFFFFFFEUL;
	}

	return initialize(NULL);
}
*/
import "C"

import "unsafe"

// initializeWithoutArguments starts a driver the way some of them insist on:
// with no arguments at all. It returns the driver's return value.
func initializeWithoutArguments(path string) uint {
	name := C.CString(path)
	defer C.free(unsafe.Pointer(name))

	return uint(C.initialize_without_arguments(name))
}
