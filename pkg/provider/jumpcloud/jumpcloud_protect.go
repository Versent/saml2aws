package jumpcloud

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/pkg/errors"
)

type JumpCloudPushResponse struct {
	ID          string    `json:"id"`
	ExpiresAt   time.Time `json:"expiresAt"`
	InitiatedAt time.Time `json:"initiatedAt"`
	Status      string    `json:"status"`
	UserId      string    `json:"userId"`
}

func (jc *Client) jumpCloudProtectAuth(submitUrl string, xsrfToken string) (*http.Response, error) {
	jumpCloudParsedURL, err := url.Parse(submitUrl)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("unable to parse submit url, url=%s", jumpCloudProtectSubmitURL))
	}

	req, err := http.NewRequest("POST", jumpCloudParsedURL.String(), emptyJSONIOReader())
	if err != nil {
		return nil, errors.Wrap(err, "error building jumpcloud protect auth request")
	}
	ensureHeaders(xsrfToken, req)

	res, err := jc.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving JumpCloud PUSH payload")
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, errors.New("error retrieving JumpCloud PUSH payload, non 200 status returned")
	}

	jpResp, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving JumpCloud PUSH payload")
	}

	jp := JumpCloudPushResponse{}
	if err := json.Unmarshal(jpResp, &jp); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal JumpCloud PUSH payload to struct")
	}

	jumpCloudParsedURL.Path = path.Join(jumpCloudParsedURL.Path, jp.ID)
	req, err = http.NewRequest("GET", jumpCloudParsedURL.String(), nil)
	ensureHeaders(xsrfToken, req)

	if err != nil {
		return nil, errors.Wrap(err, "failed to build JumpCoud PUSH polling request")
	}

	// Stay in the loop until we get something else other than "pending".
	// jp.Status can be:
	// * accepted
	// * expired
	// * denied

	for jp.Status == "pending" {
		if time.Now().UTC().After(jp.ExpiresAt) {
			return nil, errors.New("the session is expired try again")
		}

		resp, err := jc.client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "error retrieving verify response")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, errors.New(fmt.Sprintf("received non 200 http code, http code = %d", resp.StatusCode))
		}

		bytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal JumpCloud PUSH body")
		}

		if err := json.Unmarshal(bytes, &jp); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal poll result json into struct")
		}

		// sleep for 500ms before next request
		time.Sleep(500 * time.Millisecond)
	}

	if jp.Status != "accepted" {
		return nil, errors.New(fmt.Sprintf("didn't receive accepted, status=%s", jp.Status))
	}

	jumpCloudParsedURL.Path = path.Join(jumpCloudParsedURL.Path, "login")
	req, err = http.NewRequest("POST", jumpCloudParsedURL.String(), emptyJSONIOReader())
	if err != nil {
		return nil, errors.Wrap(err, "failed to build JumpCoud login request")
	}

	ensureHeaders(xsrfToken, req)
	return jc.client.Do(req)
}
