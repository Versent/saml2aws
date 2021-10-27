package page

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

type Form struct {
	URL    string
	Method string
	Values *url.Values
}

func (form *Form) BuildRequest() (*http.Request, error) {
	values := strings.NewReader(form.Values.Encode())
	req, err := http.NewRequest(form.Method, form.URL, values)
	if err != nil {
		return nil, errors.Wrap(err, "error building request")
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

func (form *Form) Submit(client *provider.HTTPClient) (*http.Response, error) {
	if req, err := form.BuildRequest(); err != nil {
		return nil, errors.Wrap(err, "error building request")
	} else if res, err := client.Do(req); err != nil {
		return nil, errors.Wrap(err, "error submitting form")
	} else {
		return res, nil
	}
}

// If the document has multiple forms, the first form with an `action` attribute will be parsed.
// You can specify the exact form using a CSS filter.
func NewFormFromDocument(doc *goquery.Document, formFilter string) (*Form, error) {
	form := Form{Method: "POST"}

	if formFilter == "" {
		formFilter = "form[action]"
	}
	formSelection := doc.Find(formFilter).First()
	if formSelection.Size() != 1 {
		return nil, fmt.Errorf("could not find form")
	}

	attrValue, ok := formSelection.Attr("action")
	if ok {
		form.URL = attrValue
	} else {
		form.URL = doc.Url.String()
	}

	attrValue, ok = formSelection.Attr("method")
	if ok {
		form.Method = strings.ToUpper(attrValue)
	}

	form.Values = &url.Values{}
	formSelection.Find("input").Each(func(_ int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}

		val, ok := s.Attr("value")
		if !ok {
			return
		}

		form.Values.Add(name, val)
	})

	return &form, nil
}

func NewFormFromResponse(res *http.Response, formFilter string) (*Form, error) {
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}
	return NewFormFromDocument(doc, formFilter)
}
