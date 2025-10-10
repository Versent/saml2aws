package page

import (
	"bytes"
	"net/url"
	"os"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
)

func TestNewFormFromDocument(t *testing.T) {
	data, err := os.ReadFile("example/multi-form.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)

	// assert the default behavior is to extract the first form with an action
	form, err := NewFormFromDocument(doc, "")
	require.Nil(t, err)
	require.Equal(t, "/form_b", form.URL)
	require.Equal(t, url.Values{"b1": []string{"rock"}, "b2": []string{"paper"}}, *form.Values)

	// assert we can provide a specific form filter
	form, err = NewFormFromDocument(doc, "#c")
	require.Nil(t, err)
	require.Equal(t, "/form_c", form.URL)
	require.Equal(t, url.Values{"c1": []string{"now"}}, *form.Values)
}
