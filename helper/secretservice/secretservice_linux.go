// Copyright (c) 2016 David Calavera

// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// https://github.com/docker/docker-credential-helpers
package secretservice

/*
#cgo pkg-config: libsecret-1
#include "secretservice_linux.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"

	"github.com/versent/saml2aws/helper/credentials"
)

// Secretservice handles secrets using Linux secret-service as a store.
type Secretservice struct{}

// Add adds new credentials to the keychain.
func (h Secretservice) Add(creds *credentials.Credentials) error {
	if creds == nil {
		return errors.New("missing credentials")
	}
	credsLabel := C.CString(credentials.CredsLabel)
	defer C.free(unsafe.Pointer(credsLabel))
	server := C.CString(creds.ServerURL)
	defer C.free(unsafe.Pointer(server))
	username := C.CString(creds.Username)
	defer C.free(unsafe.Pointer(username))
	secret := C.CString(creds.Secret)
	defer C.free(unsafe.Pointer(secret))

	if err := C.add(credsLabel, server, username, secret); err != nil {
		defer C.g_error_free(err)
		errMsg := (*C.char)(unsafe.Pointer(err.message))
		return errors.New(C.GoString(errMsg))
	}
	return nil
}

// Delete removes credentials from the store.
func (h Secretservice) Delete(serverURL string) error {
	if serverURL == "" {
		return errors.New("missing server url")
	}
	server := C.CString(serverURL)
	defer C.free(unsafe.Pointer(server))

	if err := C.delete(server); err != nil {
		defer C.g_error_free(err)
		errMsg := (*C.char)(unsafe.Pointer(err.message))
		return errors.New(C.GoString(errMsg))
	}
	return nil
}

// Get returns the username and secret to use for a given registry server URL.
func (h Secretservice) Get(serverURL string) (string, string, error) {
	if serverURL == "" {
		return "", "", errors.New("missing server url")
	}
	var username *C.char
	defer C.free(unsafe.Pointer(username))
	var secret *C.char
	defer C.free(unsafe.Pointer(secret))
	server := C.CString(serverURL)
	defer C.free(unsafe.Pointer(server))

	err := C.get(server, &username, &secret)
	if err != nil {
		defer C.g_error_free(err)
		errMsg := (*C.char)(unsafe.Pointer(err.message))
		return "", "", errors.New(C.GoString(errMsg))
	}
	user := C.GoString(username)
	pass := C.GoString(secret)
	if pass == "" {
		return "", "", credentials.ErrCredentialsNotFound
	}
	return user, pass, nil
}

// List returns the stored URLs and corresponding usernames for a given credentials label
func (h Secretservice) List() (map[string]string, error) {
	credsLabelC := C.CString(credentials.CredsLabel)
	defer C.free(unsafe.Pointer(credsLabelC))

	var pathsC **C.char
	defer C.free(unsafe.Pointer(pathsC))
	var acctsC **C.char
	defer C.free(unsafe.Pointer(acctsC))
	var listLenC C.uint
	err := C.list(credsLabelC, &pathsC, &acctsC, &listLenC)
	if err != nil {
		defer C.g_error_free(err)
		return nil, errors.New("Error from list function in secretservice_linux.c likely due to error in secretservice library")
	}
	defer C.freeListData(&pathsC, listLenC)
	defer C.freeListData(&acctsC, listLenC)

	resp := make(map[string]string)

	listLen := int(listLenC)
	if listLen == 0 {
		return resp, nil
	}
	// The maximum capacity of the following two slices is limited to (2^29)-1 to remain compatible
	// with 32-bit platforms. The size of a `*C.char` (a pointer) is 4 Byte on a 32-bit system
	// and (2^29)*4 == math.MaxInt32 + 1. -- See issue golang/go#13656
	pathTmp := (*[(1 << 29) - 1]*C.char)(unsafe.Pointer(pathsC))[:listLen:listLen]
	acctTmp := (*[(1 << 29) - 1]*C.char)(unsafe.Pointer(acctsC))[:listLen:listLen]
	for i := 0; i < listLen; i++ {
		resp[C.GoString(pathTmp[i])] = C.GoString(acctTmp[i])
	}

	return resp, nil
}

// SupportsCredentialStorage returns true since storage is supported
func (Secretservice) SupportsCredentialStorage() bool {
	return true
}
