package psu

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var goodDuoResults = `<script type="text/javascript">var duoResults = {
      devices: {"devices":[{"capabilities":["push","phone","sms"],"device":"abcdefg123456789","display_name":"Phone 1 (XXX-XXX-1234)","sms_nextcode":"1","type":"phone"},{"capabilities":["phone","sms"],"device":"987654321gfedcba","display_name":"Phone 2 (XXX-XXX-5678)","type":"phone"},{"capabilities":[],"device":"hijklmnop123456789","display_name":"12345678","type":"token"}]},
      service: 'cosign-as1.fim.psu.edu',
      referrer: 'https://as1.fim.psu.edu/idp/Authn/RemoteUser?conversation=e1s1',
      remoteuser: '',
      account_type: "dce",
      requiredFactors: unescape('dce.psu.edu,2fa'),
      satisfiedFactors: 'dce.psu.edu',
      error: 'Additional authentication is required.',
      onRedirect: function(url) {
        window.location.assign(url);
      }
    };
</script>`

func TestStringInSlice(t *testing.T) {
	needle := "needle"
	haystackA := []string{"foo", "bar", "baz", "needle"}
	haystackB := []string{"foo", "bar", "baz"}

	assert.True(t, stringInSlice(needle, haystackA), "is true")
	assert.False(t, stringInSlice(needle, haystackB), "is false")
}

func TestExtractDuoResults(t *testing.T) {

	r, err := extractDuoResults(goodDuoResults)
	assert.NoError(t, err)
	assert.Len(t, r.Devices.Devices, 3)

	_, err = extractDuoResults("")
	assert.Error(t, err)

	_, err = extractDuoResults(`var thisIsValidJson = {foo: "bar"};`)
	assert.Error(t, err)

	_, err = extractDuoResults(`var duoResults = {foo: "bar"};`)
	assert.Error(t, err)

	r, err = extractDuoResults(`var duoResults = { devices: {"devices":[]} };`)
	assert.Error(t, err)
	assert.Len(t, r.Devices.Devices, 0)
}

func TestParseDuoResults(t *testing.T) {

	dr, err := extractDuoResults(goodDuoResults)
	assert.Nil(t, err)

	duoDevices := parseDuoResults(dr)
	assert.Len(t, duoDevices, 5)

	// push
	assert.Equal(t, "push", duoDevices[0].OptionType)
	assert.Equal(t, "abcdefg123456789", duoDevices[0].Device)
	assert.Equal(t, "Duo Push to Phone 1 (XXX-XXX-1234)", duoDevices[0].Prompt)

	// phone
	assert.Equal(t, "phone", duoDevices[1].OptionType)
	assert.Equal(t, "abcdefg123456789", duoDevices[1].Device)
	assert.Equal(t, "Phone call to Phone 1 (XXX-XXX-1234)", duoDevices[1].Prompt)

	// sms with next code
	assert.Equal(t, "sms", duoDevices[3].OptionType, "sms")
	assert.Equal(t, "abcdefg123456789", duoDevices[3].Device)
	assert.Equal(t, "SMS passcodes to Phone 1 (XXX-XXX-1234) (next code starts with 1)", duoDevices[3].Prompt)

	// sms without next code
	assert.Equal(t, "sms", duoDevices[4].OptionType, "sms")
	assert.Equal(t, "987654321gfedcba", duoDevices[4].Device)
	assert.Equal(t, "SMS passcodes to Phone 2 (XXX-XXX-5678)", duoDevices[4].Prompt)
}
