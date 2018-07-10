package page

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/pkg/errors"
	"github.com/PuerkitoBio/goquery"
)


type Form struct {
	URL    string
	Method string
	Values *url.Values
}

// If the document has multiple forms, the first form with an `action` attribute will be parsed.
// You can specify the exact form using a CSS filter.
func NewFormFromDocument(doc *goquery.Document, formFilter string) (*Form, error) {
	form := Form{}

	if formFilter == "" {
		formFilter = "form[action]"
	}
	formSelection := doc.Find(formFilter).First()
	if formSelection.Size() != 1 {
		return nil, fmt.Errorf("could not find form")
	}

	if v, ok := formSelection.Attr("action"); !ok {
		return nil, fmt.Errorf("could not extract form action")
	} else {
		form.URL = v
	}

	if v, ok := formSelection.Attr("method"); ok {
		form.Method = v
	} else {
		form.Method = "POST"
	}

	form.Values = &url.Values{}
	formSelection.Find("input").Each(func(_ int, s *goquery.Selection) {
		if name, ok := s.Attr("name"); !ok {
			return
		} else if val, ok := s.Attr("value"); !ok {
			return
		} else {
			form.Values.Add(name, val)
		}
	})

	return &form, nil
}

func NewFormFromResponse(res *http.Response, formFilter string) (*Form, error) {
	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}
	return NewFormFromDocument(doc, formFilter)
}
