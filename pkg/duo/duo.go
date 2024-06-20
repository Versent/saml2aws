package duo

import (
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/tidwall/gjson"

	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

type duoDevice struct {
	id    string
	label string
}

type duoSession struct {
	sid     string
	devices []duoDevice
}

type duoTxStatus struct {
	result    string
	resultUrl string
}

func getDevices(doc *goquery.Document) (devices []duoDevice) {
	doc.Find("select[name=\"device\"]").Find("option").Each(func(i int, s *goquery.Selection) {
		id, ok := s.Attr("value")
		if ok {
			lbl := strings.TrimSpace(s.Text())
			if len(lbl) < 1 {
				lbl = id
			}
			devices = append(devices, duoDevice{id: id, label: lbl})
		}
	})
	return
}

func getDuoSession(httpClient *provider.HTTPClient, parent string, duoHost string, duoSignature string) (*duoSession, error) {
	duoSubmitURL := fmt.Sprintf("https://%s/frame/web/v1/auth", duoHost)

	duoForm := url.Values{}
	duoForm.Add("parent", parent)
	duoForm.Add("java_version", "")
	duoForm.Add("java_version", "")
	duoForm.Add("flash_version", "")
	duoForm.Add("screen_resolution_width", "1440")
	duoForm.Add("screen_resolution_height", "900")
	duoForm.Add("color_depth", "24")
	duoForm.Add("tx", duoSignature)
	duoForm.Add("is_cef_browser", "false")
	duoForm.Add("is_ipad_os", "false")
	duoForm.Add("is_user_verifying_platform_authenticator_available", "false")

	req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building duo request")
	}
	q := req.URL.Query()
	q.Add("tx", duoSignature)
	q.Add("parent", parent)
	q.Add("v", "2.6")
	req.URL.RawQuery = q.Encode()

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error sending duo request")
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing document from duo")
	}

	// body, _ := doc.Html()
	// fmt.Println("body: ", body)

	duoSID, ok := doc.Find("input[name=\"sid\"]").Attr("value")
	if !ok {
		msg := doc.Find("span[class=\"message-text\"]").Text()
		if len(msg) > 0 {
			return nil, errors.New(fmt.Sprintf("Duo Error: %s", msg))
		}
		return nil, errors.New("unable to locate sid in duo response")
	}
	duoSID = strings.TrimSpace(html.UnescapeString(duoSID))

	if len(duoSID) < 1 {
		return nil, errors.New("empty SID in Duo response")
	}

	devices := getDevices(doc)

	return &duoSession{sid: duoSID, devices: devices}, nil
}

func selectDevice(session *duoSession) string {
	cnt := len(session.devices)
	if cnt < 1 {
		// This shouldn't happen. There should be at least one device. So make a
		// wild guess.
		return "phone1"
	} else if cnt < 2 {
		return session.devices[0].id
	}

	var ids []string
	var labels []string
	for _, dev := range session.devices {
		ids = append(ids, dev.id)
		labels = append(labels, dev.label)
	}
	return ids[prompter.Choose("Select Duo MFA Device", labels)]
}

func selectFactorFn(loginDetails *creds.LoginDetails, deviceId string) func(*url.Values) {
	var token string
	duoMfaOption := 0
	var duoMfaOptions = []string{
		"Duo Push",
		"Passcode",
	}

	return func(form *url.Values) {
		if loginDetails.DuoMFAOption == "Duo Push" {
			duoMfaOption = 0
		} else if loginDetails.DuoMFAOption == "Passcode" {
			duoMfaOption = 1
		} else {
			duoMfaOption = prompter.Choose("Select a Duo MFA Option", duoMfaOptions)
		}

		if duoMfaOptions[duoMfaOption] == "Passcode" {
			token = prompter.StringRequired("Enter passcode")
		}

		form.Add("device", deviceId)

		form.Add("factor", duoMfaOptions[duoMfaOption])
		if duoMfaOptions[duoMfaOption] == "Passcode" {
			form.Add("passcode", token)
		}
	}
}

func startTx(httpClient *provider.HTTPClient, duoHost string, duoSID string, selectFactor func(*url.Values)) (duoTxId string, err error) {
	duoSubmitURL := fmt.Sprintf("https://%s/frame/prompt", duoHost)

	duoForm := url.Values{}
	duoForm.Add("sid", duoSID)
	duoForm.Add("out_of_date", "false")

	selectFactor(&duoForm)

	req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "error building duo prompt request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := httpClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving duo prompt request")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving duo prompt response")
	}

	resp := string(body)

	duoTxStat := gjson.Get(resp, "stat").String()
	duoTxId = gjson.Get(resp, "response.txid").String()
	if duoTxStat != "OK" {
		return "", errors.Wrap(err, "error authenticating duo mfa device")
	}

	return duoTxId, nil
}

func getTxStatus(httpClient *provider.HTTPClient, duoHost string, sid string, duoTxId string) (status *duoTxStatus, err error) {
	duoSubmitURL := fmt.Sprintf("https://%s/frame/status", duoHost)

	duoForm := url.Values{}
	duoForm.Add("sid", sid)
	duoForm.Add("txid", duoTxId)

	req, err := http.NewRequest("POST", duoSubmitURL, strings.NewReader(duoForm.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, "error building duo status request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "error sending duo status request")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving duo status response")
	}

	resp := string(body)

	status = &duoTxStatus{
		result:    gjson.Get(resp, "response.result").String(),
		resultUrl: gjson.Get(resp, "response.result_url").String()}
	return
}

func getTxResultJson(httpClient *provider.HTTPClient, duoHost string, sid string, duoTxId string, resultUrl string) (string, error) {
	duoRequestURL := fmt.Sprintf("https://%s%s", duoHost, resultUrl)

	duoForm := url.Values{}
	duoForm.Add("sid", sid)
	duoForm.Add("txid", duoTxId)

	req, err := http.NewRequest("POST", duoRequestURL, strings.NewReader(duoForm.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "error constructing request object to result url")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := httpClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving duo result response")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "duoResultSubmit: error retrieving body from response")
	}

	return string(body), nil
}

func VerifyDuoMfa(httpClient *provider.HTTPClient, loginDetails *creds.LoginDetails, parent string, duoHost string, duoSignature string) (string, error) {
	sigParts := strings.Split(duoSignature, ":")

	session, err := getDuoSession(httpClient, parent, duoHost, sigParts[0])
	if err != nil {
		return "", errors.Wrap(err, "error fetching Duo SID")
	}

	deviceId := selectDevice(session)
	factorFn := selectFactorFn(loginDetails, deviceId)

	duoTxId, err := startTx(httpClient, duoHost, session.sid, factorFn)
	if err != nil {
		return "", errors.Wrap(err, "error starting Duo Tx")
	}

	var status *duoTxStatus
	for {
		status, err = getTxStatus(httpClient, duoHost, session.sid, duoTxId)
		if err != nil {
			return "", errors.Wrap(err, "error checking Duo tx status")
		}

		if status.result == "FAILURE" {
			return "", errors.Wrap(err, "failed to authenticate device")
		}
		if status.result == "SUCCESS" {
			break
		}

		time.Sleep(3 * time.Second)
	}

	resultJson, err := getTxResultJson(httpClient, duoHost, session.sid, duoTxId, status.resultUrl)
	if err != nil {
		return "", errors.Wrap(err, "error getting Duo result json")
	}

	cookie := gjson.Get(resultJson, "response.cookie").String()

	return fmt.Sprintf("%s:%s", cookie, sigParts[1]), nil
}
