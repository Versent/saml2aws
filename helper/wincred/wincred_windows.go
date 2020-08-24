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
package wincred

import (
	"bytes"
	"strings"

	"github.com/GESkunkworks/gossamer3/helper/credentials"
	winc "github.com/danieljoos/wincred"
)

// Wincred handles secrets using the Windows credential service.
type Wincred struct{}

// Add adds new credentials to the windows credentials manager.
func (h Wincred) Add(creds *credentials.Credentials) error {
	g := winc.NewGenericCredential(creds.ServerURL)
	g.UserName = creds.Username
	g.CredentialBlob = []byte(creds.Secret)
	g.Persist = winc.PersistLocalMachine
	g.Attributes = []winc.CredentialAttribute{{"label", []byte(credentials.CredsLabel)}}

	return g.Write()
}

// Delete removes credentials from the windows credentials manager.
func (h Wincred) Delete(serverURL string) error {
	g, err := winc.GetGenericCredential(serverURL)
	if g == nil {
		return nil
	}
	if err != nil {
		return err
	}
	return g.Delete()
}

// Get retrieves credentials from the windows credentials manager.
func (h Wincred) Get(serverURL string) (string, string, error) {
	g, _ := winc.GetGenericCredential(serverURL)
	if g == nil {
		return "", "", credentials.ErrCredentialsNotFound
	}
	for _, attr := range g.Attributes {
		if strings.Compare(attr.Keyword, "label") == 0 &&
			bytes.Compare(attr.Value, []byte(credentials.CredsLabel)) == 0 {

			return g.UserName, string(g.CredentialBlob), nil
		}
	}
	return "", "", credentials.ErrCredentialsNotFound
}

// List returns the stored URLs and corresponding usernames for a given credentials label.
func (h Wincred) List() (map[string]string, error) {
	creds, err := winc.List()
	if err != nil {
		return nil, err
	}

	resp := make(map[string]string)
	for i := range creds {
		attrs := creds[i].Attributes
		for _, attr := range attrs {
			if strings.Compare(attr.Keyword, "label") == 0 &&
				bytes.Compare(attr.Value, []byte(credentials.CredsLabel)) == 0 {

				resp[creds[i].TargetName] = creds[i].UserName
			}
		}

	}

	return resp, nil
}

// SupportsCredentialsStorage returns true since storage is supported
func (Wincred) SupportsCredentialStorage() bool {
	return true
}
