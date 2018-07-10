package pingfed

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
)

var extractAuthSubmitURLTests = []struct {
        f        string // input html file
        expected string // expected url
}{
	{"example/loginpage.html", "https://example.com/relative/login"},
	{"example/loginpage_absolute.html", "https://other.example.com/login"},
}

func TestExtractAuthSubmitURL(t *testing.T) {
	for _, tt := range extractAuthSubmitURLTests {
		data, err := ioutil.ReadFile(tt.f)
		require.Nil(t, err)

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
		require.Nil(t, err)

		url, err := extractAuthSubmitURL("https://example.com", doc)
		require.Nil(t, err)
		require.Equal(t, tt.expected, url)
	}
}
