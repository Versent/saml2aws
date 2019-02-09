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
#include <Security/Security.h>

struct Server {
  SecProtocolType proto;
  char *host;
  char *path;
  unsigned int port;
};

char *keychain_add(struct Server *server, char *label, char *username, char *secret);
char *keychain_get(struct Server *server, unsigned int *username_l, char **username, unsigned int *secret_l, char **secret);
char *keychain_delete(struct Server *server);
char *keychain_list(char *credsLabel, char *** data, char *** accts, unsigned int *list_l);
void freeListData(char *** data, unsigned int length);