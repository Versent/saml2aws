package pingone

import (
	"bytes"
	"os"
	"reflect"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
)

var docTests = []struct {
	fn       func(*goquery.Document) bool
	file     string
	expected bool
}{
	{docIsFormSelectDevice, "example/selectdevice.html", true},
}

func TestMakeAbsoluteURL(t *testing.T) {
	url1, _ := makeAbsoluteURL("/pingid/ppm/devices", "https://authentication.pingone.com")
	url2, _ := makeAbsoluteURL("/pingid/ppm/devices", "https://authentication.pingone.com/")
	url3, _ := makeAbsoluteURL("https://authentication.pingone.com/pingid/ppm/devices", "https://authentication.pingone.com/")

	require.Equal(t, url1, "https://authentication.pingone.com/pingid/ppm/devices")
	require.Equal(t, url2, "https://authentication.pingone.com/pingid/ppm/devices")
	require.Equal(t, url3, "https://authentication.pingone.com/pingid/ppm/devices")
}

func TestDocTypes(t *testing.T) {
	for _, tt := range docTests {
		data, err := os.ReadFile(tt.file)
		require.Nil(t, err)

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
		require.Nil(t, err)

		if tt.fn(doc) != tt.expected {
			t.Errorf("expect doc check of %v to be %v", tt.file, tt.expected)
		}
	}
}

var deviceNameTests = []struct {
	file     string
	expected map[string]string
}{
	{"example/selectdevice.html", map[string]string{"iPhone": "3270134077889335000", "Android": "3964291169487703000"}},
	{"example/selectdevicebutton.html", map[string]string{"iPhone": "3270134077889335000", "Android": "3964291169487703000"}},
}

func TestFindDeviceMap(t *testing.T) {
	for _, tt := range deviceNameTests {
		data, err := os.ReadFile(tt.file)
		require.Nil(t, err)

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
		require.Nil(t, err)

		deviceMap := findDeviceMap(doc)

		eq := reflect.DeepEqual(deviceMap, tt.expected)

		if eq != true {
			t.Errorf("expected deviceMap %v to be %v", deviceMap, tt.expected)
		}
	}
}
