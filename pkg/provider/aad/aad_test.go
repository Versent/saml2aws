package aad

import (
	"bytes"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	mrand "math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"text/template"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/mocks"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
	"github.com/versent/saml2aws/v2/pkg/provider"
)

var once sync.Once

// example values are mainly url safe base64 secure random bytes to illustrate payload values
type FixtureData struct {
	ApplicationId                         string // 31eaeb21-4b55-4390-a8fe-21a780dfedc7
	State                                 string // Su7ku6ROOSiNe3BN16zhOYZGfQ8dC-wihtcvx4aGi9PNmAyePGemK_yT9H0CapK8HtwS83mbmlltNOknoftpDQ6gP4reH9cyEI5LufKgJ6wozu4msl0npXJZLAO14yUxUjLtxgHuAlvY91umliqPCEGHSwrKYm2piA6HZXqR5wIIK5LiSC_N7k7BOULpDE9qassFTfqTFF5kRNsrSmukREVdOZeNKr-RIPrNOASnH-nggHo-h7HiExFSJEZE8CQBG8JZ5PNcZbaQ2SZeHScKtUr8KCVyoaMdZ5xwXQ2G57VKF5DZsfQfMEPIspnbNkdqwRBHYIJZnX9JakvcKPXckEHriCTL1yN1_cLgBrPA62YBSim80GR8AMOx4Ij7lIQRTy-aLyDGpp6E3PdvTY72W51b1J5vzYl9XslyfRIWj1h_Q5cLlC03k5VJ8rIpeWgUIiEFgOZeDWQctR370JauwvJTfrOFE2yQXvXgU1zFhIvuEy3HhfoYPtlwGfLpeu1Czm-8PkMF24CdgIBRFIn2Rg4Pqt1KDDve7eKygqF79Qgiq-Hm5qGDdURKUF-Ei-Abft7pRs-A0hai27KtOCoJ9YUSoBrdLRyqLXvWkIWz5eeafRqIPlcSV32_jqbkZVJxj_jRdHrJCOSgtETyk1h_zAU_pLmhXfPuMcrIWZMbFTwGrC-xwPVRnaSGzztCVsXiiwWgtUAzzJIuNQSQ9DPpUIzdlOznwi8sVNMw51MXaPx6Qdgv-1pTJX-Hr78lJJRzaKPMBALsgoco9L-yJju7PCnBEJMOucw_J632ofAuzEOox7vfQ0dWVDg5VOOkFsqb0mWSnllFJWkk27wzBZ4-csABoSD8AkrnhnLC5ggCFNh16rPxPDejOfDvdyEV7-zXPJFgJP5rSP8n3kKb27Co10MISI0eWzHdghzbWpJSu78XBElT-5h6w_d4bdZfxgn-UxXCFz7yDQGQ5hKF-q2xx4R3uYn8Xg-5q2Es0OLJsHg5QOVYJ0DYJtcZqtlctP__BBrR3boFT-k0rytvqleuZy3ErSMBSGfCvh9C32bYgIM
	UaId                                  string // b96e46687a7350c07d4709e1c54b87d4
	Ctx                                   string // tkdXR5EHHAyb8jhx9XgSfRWpRASqfOc-2WnbZ6N8zxXgudxf70uzJ_izSIAcJylZcalEj4X60sW8naje072dEviyjpvUQu29mjCI80201-x4jijCexX-0_xphUkrcyDnMNFdpdjlhVeJG7ZNKKP2KxrrIDOX5fEFzUi8Sn1I4iwzJWkyOqznTQj7Na7mLhduZwcPX-slpOaNCx11x5CeyXgNmmDY5YNQxCHPsbGB6UeTMkfgBsQXpgLI-ppUuRf-wc7fYfc7pw-VifZggoEKEubdSVsjNS2tAFJKeoX6CzaJ8q2_KZh5T3HMcjhmlxNQ_tsqSb4uc69eZEdb227vk7D57n8FYjmrozMtVFX-XvrYTtbCUQZQWfRaSF14ZgkBUcqS0cQqEXJElvP2yFl8yBLsNVtB7y5pl6yjaIWAh7PzksFPRHUr6WpAmtfH1zSJguIjMpKrId4AjCXClU4y38k1QaVpXIr_H2TK0I3Se36Pc5jJ2urAeCMNSz7Dkb4ETnFoG77jbX5hmc-KsOw3y-SH1b3xgmSXryI8fC5WQnUMTRYKSP7A2GSP507O7jQKBun5lU69L4EwC78e5YuSwK9wlO53THzM_HW0Mn35uD2dGolL8X5AgK72PZkMuLNkNpmc-f2gjZmcBgBlK6A7tJW18WzUsJ0q2mXZFOJB9TVM8LIf58vt-CoggKxgTOeyL9qOVlRlUWt5Cz9HPDR_VazS0ZPeL6e3Xp8O5XzVMPKNp89U3H5BJ7EXrpGmqGasPvxugfHY5mBwA4YyoZeGr2fF9aDcnKK2PiRmUAGvo1GUfy4913uMnDff9riTjNCu9Yy-C7FyWcAl2VFhadI3PwTq3Z05038lGnFEOPsOFKJJrQ3Whtj9G1k-l7idQd3WVMwqjQ3yyGbj_Rl1ilzd0PcxNZqTZxrHA1N3Xi7BdusfvJ2BnPk-LONKfTteFrcZaylSmYtE6h7poo6I8cjTx_aHMkkXN-zg5AvcLWPwOKK_qUdjrGbiSB52G7b4yRHJnTxvNe1NgXFZC2xdDEbY8Pj9cdZzRHH-bpZebaO1MtI
	OpenIdConnectAuthenticationProperties string // nNB2aD/pc12XrIZ8Ga9i9dI8g0/Kb4WPCLK1jIXEoYH/AFVTojIEvz5LMmVit8YETkHevIXJ+Ye/qTuhlYW4MCMs0g3GBNrtx/cS/NX0yAg08lbQYEWnq0ddhT6NhhysDq7s7PPdcCok8x/wf2LDTE5n4r53C9b+q6ArCLqD8xDb9snlTH3LSsrsgfOoa+GOOTG+5HsnC2kP+yZT2YK9Ifk+5bZVF0yVT5T2WaTVxsWva3+LNcGPYPDR56as8KJ5UvUuvR+bBInw7yX2fzFkfgC8bc8cvlGI1QRtzcTc0KLqayyplFa7XV2yhKv9wY1uEh6RigJX4FJdKzaX84juPKi/RA9rU37KUwnKdZlZ4762YzIqGrRTBwJZUHHisu1O7ooGgA+x2gQ1VY9cAkCQiq5/VgSyZ4wCJniBinwlBwxh9/thBawgHTTThpMfQSXEMWUyAGt8SoWz9FHgF9hEhte1kifXkEr7srrtUwuaxhdYvsLlZKcVZhttgbQR/js1/ZMFHEIRTPnfWZLq9atRiA==
	Nonce                                 string // 1577836800._ekiEOvOQz4YQL8FvAZsdQ
	SFT                                   string // vZXtKGAHg7jYK1oppkd43__si0KvHN0i02_TENgVBl_j1mYs0APdQ4bYjh3PcH-1Coouq384kZnIp2MXyS87NmOpwS_Nyb-ntXeQCPvDn0Ubiss7XvvYgq1ReeeyBCuzaE9kUoUlDnMU5D1dx_-KnFHh5evlsRrDBPLRWhG7Kt3fauAg5nvNyKXSF0DA90k8I4oMFaiaNe9ObjmkilRnPUBu3G2p1__BrsgJCGMXv9eZc2d3ANGz6ftwnTrK2OMODyjd5vXuDkQSTu1vZgbSWTkb_prS80o_B3vpvEt1Zord1xPZxTK262-oeUIpFnVjV4sSGnL_smwbA7_qHxSTwmY_1ZCbjuvJTXg1OOKS36GcqwX4h6kMHPAAGwMvvUlMXicqE4xFwF-1yOzFW7L8vPDMHxJtapY_Q94g2pVlKv3uwa0jF3Rk_RddhRZ4mzp7n319_Uq1WcgX-9lvsBoLOtadWstlvKPZ6Y4rUzESAYwOlM8OQ3HGWvvArBqd33o2MFKwqKcpXX73F07QR8qS6A
	ClientRequestId                       string // 5ec023a2-663b-4168-9cb0-fe7c400b79fa
	SessionId                             string // dda35067-5d88-4660-9f5f-f68f4c751cca
	ApiCanary                             string // ype6puaxP6rNV_JtHkyBUEop77KMbSWCBsi4sJmIxLTN0z8NsvLH6ihw1MMT49eTKsCX-RIQl5_vfEllanIyaKijtOGfCHVfgUW0UZ_chdfnuokV9Q9_bUMl-43TLKlDYN0iEwVxQRyIcEYwFISHaYgY14wHe9LkRLmrQt2BlOaMtDQOT8qD-tH7urTxZ8Uj20UKT7wujO20V3_6teiL86s_V4_DDtPta2N355Pz2pFWaVfS7_2a6zf3YnY4wyEHbN_xcT2RBjo
	Canary                                string // Llh9ry4LOBrmLXLlwgbPhxdrOcd4l5HeTPBVR9tG8vg
	InstrumentationKey                    string // 1cc3422557e1ba83979ee678092399df-8d876a22-d379-46d2-b066-17a83683d9be-2529
	Code                                  string // HIdSBXkPCB2Q2oLUjtCiET6Ogb7yPfRumZkWGgmWKrtfCnbKAreOR_o0GCYDBo5ebqe9OrrXLZz1OfPJDlMSR2uM_t_a5Pyw0Kf86KB2P6StMyWr-nHlY2NM7iK9c1TUCevEWhbFIdAwPgxtpt91IiG7rpoapTobUHLqpcVHNahAHE7rPkVXnFGBq6khbsCzgHk1vc2LgC79AQk1m7Mxf3KVDgglpIIVkk6NQpdc_J1pUzjX2WLHh_k_UHK4O9ygf07ELTZJz5Z16ZZJMSs5aOZhurzbOh8mGZeruaHr8FnmK_23Iqx6o_YdehMi5_GcxQjdGD1EM66X27kwghufJBRAa66nmOv3oYI1ILkY29mSnuKnEZDO715zITwdaahrOW0dqXwMR2QtutwxoEZJvJbwXWRrGW8yiNKav03a_j4duY1kVvNmOmT6gE6oaEKboWHxjGDUCCeNJ4-8mtTYnG0rVFrF8Y2-Prq4n23LrbQKfgteD_MG12eihJaQHPCjQgyIZoCcf9unWC5ty0duSNNsb0_GMWc3tGI2bfqNFSFvSvv8BYtyPTjYBhecgBodMr5haKM3pKXh0ZRAqms7hV8myViWlZtIs-pTRAXghPEUBG0Yzg1lPME-KuZOmP-RYggjzyO9IL5suoLIgacXqUI6nJA
	IdToken                               string // Wz0fWBNb4WkJN_z-97b6LQ5nu6tNmQJC1UGQ7ewy9j7nEO7kMYwA7lA8sQdzO7piZawRLfB1Rgcu0B66RSpWND7yiQYyx99ra-4uTJLPUM7Ngw1ELjExod0nttyMc4f-4RZdWe3KkuORiHdarA27PdP1xhxChyrGdNfZtPNJSLwEvmoSMIYErVbrlhu8i0ZsS5C-zGFiWxRxl6jDDZRXeRFi-DQRDm5qeMfbUDcg6V2TV9BDilkyH_P0o5rHQ7zSjK7YZj20LyLsXXpPadEwUtkE38br2ezG9scSXrqE0UXGgu8T5DvNVBJjwGtFfOBuQrGEMQ5y6LZROMTY-m_ZqE0kevU9vekeV3dw6i9b4O7_l1fwih0Um46-gxlELv32Vb4Wgcl9mqeM1yXoIawyPMGrsqQ1CnHcTNccDj9G5UCAF2zw54sqg2e3L5Zvl-7KVsPGM-A3h241GfiWYvQ_VHpsoR1PZE1DcfkaHusvu_OB8lUAuFbLnerqLo-73rVkhNGH2YxNXWWB7hanx1zDuXEZ1G9gJNnMWQZN-pPRgYylKIL-5Fr1K3yN1Y1l4P8clESRzwA1gvZON7UuFGcn289BfeiAS-Hc6XiGOwHLd0aBLN-wtmzA_w4CnKmBieEAuz8MJGT3mjv4PXcaxEXkaqH_avo4iBnRJAp7hd5J6xQJ0t_vfWHqHEbSLomHTcM9Dk24_PuHIDJS93eJ0Jx-JYtWO0xTpB6rUc-arHyM4x38_l_3NHZRSI2_ut_FqeV1qetD7__-k7sjGxmM6BkqncjRVqQS14B-OeO15ali-VBHvUfi36GAsdQwboGnEzfa7yXmWe31P2qazPZfYa-IOkJfaj4v7wJ_kAKwqB5xfFRJvgs8gl3KHEOQHnC3V3oNXf6vY2RpgBO0b5cmmkJblEtRVChyABU0U1djjT_REw1S97mKsnJJIBA2iPyUHMTsk6jGddx6DHj86sD497yhN4TinSloJTlsrMlH1LlYaZrFmLG2qmBylL4_cE9m8-sxlIuJYPbGcDXRHuTiEwR8XHM9LGMwf9rhMOVIjt8XyXUbmED0Pt7uy4t75mzP2YAUfwdohnFNXzV-ZbaUTMVQurSNh_RAL6gLFbjsXc8cmJ1-5PdR9ohrhszN9oYZTTW-9OZ2TGk0anh9APqoKIecORBHYxdVmnJAxIZIB2cKLfqD74kMFlfkAYmJSb1yLV3Hfgv2EJYDxY-neRhopjm7-R52ESx38d7JaZL7ubAuUi7NqNN-CX8UXzZ6_GBvVLYtQf80ARnQew07fygQZ8mR8k7NAZqAvnN4ebItVabQ0vtzcEii_dRr242J38XRM_dClEipbLEluoUVM1-E9hMnhDKqHu0IHT0m5y7asYYsdF-QCGU2FxDTQ0QSKPcyDoZASP74-UIk6S26an4FIM7Ojc9__1Pu3DQgPYvKNxw7mv5FYXPStJm-MhAiTXo1LZGN2Po3wYLfWbhVm9q6bEFdy0-e8UqUT-tXyk3AwwC-LpfpkmmJiotH3mmtIWoZZ3dN2UaZz2tyJJaSD7yPcH-elgIn5mwv90DF1XvOgpB51GvHElc0lUykqoRPLQeEWMYKCX0fPnQ-si21nUx1ko6nZcnvFlkR06Ik41vWBSDpb0NbFXx-Jz94TPREUkUqfZspK3vLsG0UPj1bawWa6dFXEgmdys4mzZurEZGLbiiFnHO8N47qtjZul6l53_92ZFsj0MOBNgPp4qWIXi1PhJ3PJSSbnrR8rW-l3uBArTW56TlxsP7exr6TMn3C7ZfzO7G2tD1ifEiZ_0qGj80nn7ltrkfZZlc6HsrQri4LiQ4NgU85ikofugB7F42W07-9HDEJsyCuG6qdDY33EiufsdmNPb-mogeN2ELL9NSiQ1zjRjkjG8bcls-hMJbjP_GDXvjce6k_QdPK3fvyxgXvqRBGIwwXxDXmnSCn8vLiY8c20F_SyBXFfRmNtGCu-cGeoPFDX766DXPod5JYb2RABKCbJN7wE8wans4cH_nZHS_1QQyWtjkxStrFC141DUR6PIzKxO4J2KNeMqX4fk5fhHZPriZtkJHuRaRU_Lx6TlMU6n23KdrwJJWhmTN7UUxXzQvCgVO2GE6YdxDlFtVC6X7vO0rZAStqXCGK3Hq1jE1aFfpIFakl9JuBaPege6sYGdM5dwQHaGY7rlqOxVatsVG0pmE89o8QLiFJSz_0v9BVHM2_G1cl2797Kfm1QRSD8Hqt1Iq7ruD9VdQLlFN0mwc3Dt0RdRWlcxHdyFVjZj08vhiUoAhRsjMljdwRldcW8Y8SbZ7HpgifL2PZKKBFcJ8575ytN7Ft2w8QqBi6kRMqxPGa07HsL7AngavD_CXhrxKneES8xDuPzIFCleYWy9yKXVFrAHJUic4J174D57v6DtgNfHbvUaqJWX7qwlNIjeCqaPcj82GH0RYAqVeJShFhGqNw0VwyMMYhotBQdFJQkRBtllPnshj4Pw6TuwSxtVyDvSkfZmOA65vkduk1D4uEBEVt4CdiZgTMzEESD4Pt_LvfBHe4YFHaTU9J7Y3Wj7m44xlj9WL10XM2V8jGPypXuskv46-T-rdZdfgRzRMjM7r-5vlYCli-48YrbB47Z1scJ18lMTeE1G-0E6473JZjg4TGtAhYwFm_AcbsMlX1XLc
	SessionState                          string // d2371e2d-9bcd-4647-abf3-aa2eace51a9f
	UrlFederationRedirect                 string // https://sts.exampledomain.com/adfs/ls/?example-parameter=example-value
	UrlSkipMfaRegistration                string // https://login.microsoftonline.com/common/resume?ctx={{.Ctx}}\u0026flowtoken={{.SFT}}\u0026skipmfaregistration=1
	UrlGetCredentialType                  string // https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US
	UrlPost                               string // https://login.microsoftonline.com/common/login
	UrlBeginAuth                          string // https://login.microsoftonline.com/common/SAS/BeginAuth
	UrlEndAuth                            string // https://login.microsoftonline.com/common/SAS/EndAuth
	UrlProcessAuth                        string // https://login.microsoftonline.com/common/SAS/ProcessAuth
	UrlHiddenForm                         string // https://account.activedirectory.windowsazure.com/
	UrlSamlRequest                        string // https://login.microsoftonline.com/{{.ApplicationId}}/saml2?SAMLRequest={{.SAMLRequestPayload}}
	TenantId                              string // 0cfbdd7a-1d78-47ea-b458-8aa3c2558727
	SosId                                 string // 7f55cb4c-c904-4255-8d26-faa8da77c492
	ProofUpToken                          string // UVrFbiiZj6kdD6oWm4k87CkipgjEbKhlq_dKoMTo8p0TRCf4utimEAnOizRQ7qAoHaotT08os5kctHfJhXw7dkactSsYjtYo9Lt_1vlPPmZ8i0FtfrwjMeztp0sMY6PHkfRO_sWIHR2bsvIpjaKqqNTJ8PZCuwNmfR8Tx2Jdud3F1FcUgkF3-MG5omxJR7oaueRn1SvnjR-sWEleKptBqLTFnVwNeY8kVfpiKV4liNACZkWc9N5CJRC7HO4aLHVUkKcWaCERUZWeaHh0Bdk_aHSZFll1C6yBv0v4IIJfTQuCOdRMXmqvSpxpRUcwgZ7vdY6krAYUAV8SG926Fptr3if69AM5GHxKN4AlyNNJZ5ghv0yqwI4aGTg1vsanq0q8ZE80TOCBZdMz39Tr_J5MKMW2HO7lEMPtZYBCYwz3Z4nzbgWo9aB65GcxNcnzXgBMeiwjgxQphpFahbj89Rc8H0PWbN4Yhh-aDlv_UMwd2lp1I98hxdEn-8uA56xCE4l1647RuwSiCIfzE_6dYxXm8Q
	UserName                              string // exampleuser@exampledomain.com
	UserNameUrlEncoded                    string // exampleuser%40exampledomain.com
}

var fixtureData *FixtureData

func genFixtureData() *FixtureData {
	once.Do(func() {
		fixtureData = &FixtureData{
			ApplicationId:                         genUUID(),
			State:                                 genBase64Fixture(800),
			UaId:                                  genHexFixture(16),
			Ctx:                                   genBase64Fixture(800),
			OpenIdConnectAuthenticationProperties: genBase64Fixture(400),
			Nonce:                                 "1577836800" + "." + genBase64Fixture(16),
			SFT:                                   genBase64Fixture(400),
			ClientRequestId:                       genUUID(),
			SessionId:                             genUUID(),
			ApiCanary:                             genBase64Fixture(200),
			Canary:                                genBase64Fixture(32),
			InstrumentationKey:                    genHexFixture(16) + "-" + genUUID() + "-" + genIntFixture(4),
			Code:                                  genBase64Fixture(500),
			IdToken:                               genBase64Fixture(2000),
			SessionState:                          genUUID(),
			TenantId:                              genUUID(),
			SosId:                                 genUUID(),
			ProofUpToken:                          genBase64Fixture(400),
			UserName:                              "exampleuser@exampledomain.com",
			UserNameUrlEncoded:                    "exampleuser%40exampledomain.com",
		}
	})
	return fixtureData
}

func Test_fullUrl(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	ac, _ := setupTestClient(t, ts)

	res, err := ac.client.Get(ts.URL + "/Dummy")
	require.Nil(t, err)

	require.Equal(t, ac.fullUrl(res, "/Only-Path"), ts.URL+"/Only-Path")
	require.Equal(t, ac.fullUrl(res, "/"), ts.URL+"/")
	require.Equal(t, ac.fullUrl(res, "https://domain.com/"), "https://domain.com/")
	require.Equal(t, ac.fullUrl(res, "https://domain.com"), "https://domain.com")
	require.Equal(t, ac.fullUrl(res, "https://domain.com/With-Path"), "https://domain.com/With-Path")
}

func Test_isHiddenForm(t *testing.T) {
	fixtureData := genFixtureData()
	template, err := template.ParseFiles("testdata/HiddenForm.html")
	require.Nil(t, err)
	var tpl bytes.Buffer
	err = template.Execute(&tpl, fixtureData)
	require.Nil(t, err)

	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	ac := Client{client: &provider.HTTPClient{Client: http.Client{}, Options: opts}}

	require.True(t, ac.isHiddenForm(tpl.String()))
}

func Test_requestGetCredentialType(t *testing.T) {
	t.Run("ADFS login", func(t *testing.T) {
		fixtureData := genFixtureData()
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeFixtureBytes(t, w, r, "GetCredentialType_adfs.json", FixtureData{
				UrlFederationRedirect: "/adfsLogin",
			})
		}))
		defer ts.Close()

		ac, loginDetails := setupTestClient(t, ts)

		// payload from ConvergedSignIn page
		convergedResponse := ConvergedResponse{
			URLGetCredentialType: ts.URL + fixtureData.UrlGetCredentialType,
			APICanary:            fixtureData.ApiCanary,
			CorrelationID:        fixtureData.ClientRequestId,
			Hpgact:               0,
			Hpgid:                0,
			SessionID:            fixtureData.SessionId,
			SCtx:                 fixtureData.Ctx,
			SFT:                  fixtureData.SFT,
		}
		getCredentialTypeResponse, _, err := ac.requestGetCredentialType("https://referer.com", loginDetails, &convergedResponse)
		require.Nil(t, err)

		require.Equal(t, getCredentialTypeResponse.Username, fixtureData.UserName)
		require.NotEmpty(t, getCredentialTypeResponse.Credentials.FederationRedirectURL)
		require.Equal(t, getCredentialTypeResponse.Credentials.FederationRedirectURL, fixtureData.UrlFederationRedirect)
	})
	t.Run("Default login", func(t *testing.T) {
		fixtureData := genFixtureData()
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeFixtureBytes(t, w, r, "GetCredentialType_default.json", FixtureData{})
		}))
		defer ts.Close()

		ac, loginDetails := setupTestClient(t, ts)

		// payload from ConvergedSignIn page
		convergedResponse := ConvergedResponse{
			URLGetCredentialType: ts.URL + fixtureData.UrlGetCredentialType,
			APICanary:            fixtureData.ApiCanary,
			CorrelationID:        fixtureData.ClientRequestId,
			Hpgact:               0,
			Hpgid:                0,
			SessionID:            fixtureData.SessionId,
			SCtx:                 fixtureData.Ctx,
			SFT:                  fixtureData.SFT,
		}
		getCredentialTypeResponse, _, err := ac.requestGetCredentialType("https://referer.com", loginDetails, &convergedResponse)
		require.Nil(t, err)

		require.Equal(t, getCredentialTypeResponse.Username, fixtureData.UserName)
		require.Empty(t, getCredentialTypeResponse.Credentials.FederationRedirectURL)
		require.Equal(t, getCredentialTypeResponse.Credentials.FederationRedirectURL, fixtureData.UrlFederationRedirect)
	})
}

func Test_Authenticate(t *testing.T) {
	t.Run("Default login with KMSI but no MFA", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/index", "/applications/redirecttofederatedapplication.aspx":
				writeFixtureBytes(t, w, r, "ConvergedSignIn.html", FixtureData{
					UrlPost:              "/defaultLogin",
					UrlGetCredentialType: "/getCredentialType",
				})
			case "/getCredentialType":
				writeFixtureBytes(t, w, r, "GetCredentialType_default.json", FixtureData{})
			case "/defaultLogin":
				writeFixtureBytes(t, w, r, "KmsiInterrupt.html", FixtureData{
					UrlPost: "/hForm",
				})
			case "/hForm":
				writeFixtureBytes(t, w, r, "HiddenForm.html", FixtureData{
					UrlHiddenForm: "/sRequest",
				})
			case "/sRequest":
				writeFixtureBytes(t, w, r, "SAMLRequest.html", FixtureData{
					UrlSamlRequest: "/sResponse?SAMLRequest=ExampleValue",
				})
			case "/sResponse":
				writeFixtureBytes(t, w, r, "SAMLResponse.html", FixtureData{})
			default:
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			}
		}))
		defer ts.Close()

		ac, loginDetails := setupTestClient(t, ts)
		got, err := ac.Authenticate(loginDetails)
		require.Nil(t, err)
		require.NotEmpty(t, got)
	})
	t.Run("Default login with KMSI but skip MFA", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/index", "/applications/redirecttofederatedapplication.aspx":
				writeFixtureBytes(t, w, r, "ConvergedSignIn.html", FixtureData{
					UrlPost:              "/defaultLogin",
					UrlGetCredentialType: "/getCredentialType",
				})
			case "/getCredentialType":
				writeFixtureBytes(t, w, r, "GetCredentialType_default.json", FixtureData{})
			case "/defaultLogin":
				writeFixtureBytes(t, w, r, "ConvergedProofUpRedirect.html", FixtureData{
					UrlSkipMfaRegistration: "/skipMfaRegistration",
				})
			case "/skipMfaRegistration":
				writeFixtureBytes(t, w, r, "KmsiInterrupt.html", FixtureData{
					UrlPost: "/hForm",
				})
			case "/hForm":
				writeFixtureBytes(t, w, r, "HiddenForm.html", FixtureData{
					UrlHiddenForm: "/sRequest",
				})
			case "/sRequest":
				writeFixtureBytes(t, w, r, "SAMLRequest.html", FixtureData{
					UrlSamlRequest: "/sResponse?SAMLRequest=ExampleValue",
				})
			case "/sResponse":
				writeFixtureBytes(t, w, r, "SAMLResponse.html", FixtureData{})
			default:
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			}
		}))
		defer ts.Close()

		ac, loginDetails := setupTestClient(t, ts)
		got, err := ac.Authenticate(loginDetails)
		require.Nil(t, err)
		require.NotEmpty(t, got)
	})
	t.Run("Default login with KMSI and MFA", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/index", "/applications/redirecttofederatedapplication.aspx":
				writeFixtureBytes(t, w, r, "ConvergedSignIn.html", FixtureData{
					UrlPost:              "/defaultLogin",
					UrlGetCredentialType: "/getCredentialType",
				})
			case "/getCredentialType":
				writeFixtureBytes(t, w, r, "GetCredentialType_default.json", FixtureData{})
			case "/defaultLogin":
				writeFixtureBytes(t, w, r, "KmsiInterrupt.html", FixtureData{
					UrlPost: "/hForm",
				})
			case "/hForm":
				writeFixtureBytes(t, w, r, "HiddenForm.html", FixtureData{
					UrlHiddenForm: "/sRequest",
				})
			case "/sRequest":
				writeFixtureBytes(t, w, r, "SAMLRequest.html", FixtureData{
					UrlSamlRequest: "/sResponse?SAMLRequest=ExampleValue",
				})
			case "/sResponse":
				writeFixtureBytes(t, w, r, "ConvergedTFA.html", FixtureData{
					UrlPost:      "/processAuth",
					UrlBeginAuth: "/beginAuth",
					UrlEndAuth:   "/endAuth",
				})
			case "/beginAuth":
				writeFixtureBytes(t, w, r, "BeginAuth.json", FixtureData{})
			case "/endAuth":
				writeFixtureBytes(t, w, r, "EndAuth.json", FixtureData{})
			case "/processAuth":
				writeFixtureBytes(t, w, r, "SAMLResponse.html", FixtureData{})
			default:
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			}
		}))
		defer ts.Close()

		pr := &mocks.Prompter{}
		prompter.SetPrompter(pr)
		pr.Mock.On("StringRequired", "Enter verification code").Return("000000")

		ac, loginDetails := setupTestClient(t, ts)
		got, err := ac.Authenticate(loginDetails)
		require.Nil(t, err)
		require.NotEmpty(t, got)
	})
	t.Run("ADFS login with KMSI and MFA", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/index", "/applications/redirecttofederatedapplication.aspx":
				writeFixtureBytes(t, w, r, "ConvergedSignIn.html", FixtureData{
					UrlPost:              "/defaultLogin",
					UrlGetCredentialType: "/getCredentialType",
				})
			case "/getCredentialType":
				writeFixtureBytes(t, w, r, "GetCredentialType_adfs.json", FixtureData{
					UrlFederationRedirect: "/adfsLogin",
				})
			case "/adfsLogin":
				writeFixtureBytes(t, w, r, "ADFS.html", FixtureData{
					UrlPost: "/adfsTrust",
				})
			case "/adfsTrust":
				writeFixtureBytes(t, w, r, "ADFStrust.html", FixtureData{
					UrlPost: "/adfsSAML",
				})
			case "/adfsSAML":
				writeFixtureBytes(t, w, r, "KmsiInterrupt.html", FixtureData{
					UrlPost: "/hForm",
				})
			case "/hForm":
				writeFixtureBytes(t, w, r, "HiddenForm.html", FixtureData{
					UrlHiddenForm: "/sRequest",
				})
			case "/sRequest":
				writeFixtureBytes(t, w, r, "SAMLRequest.html", FixtureData{
					UrlSamlRequest: "/sResponse?SAMLRequest=ExampleValue",
				})
			case "/sResponse":
				writeFixtureBytes(t, w, r, "ConvergedTFA.html", FixtureData{
					UrlPost:      "/processAuth",
					UrlBeginAuth: "/beginAuth",
					UrlEndAuth:   "/endAuth",
				})
			case "/beginAuth":
				writeFixtureBytes(t, w, r, "BeginAuth.json", FixtureData{})
			case "/endAuth":
				writeFixtureBytes(t, w, r, "EndAuth.json", FixtureData{})
			case "/processAuth":
				writeFixtureBytes(t, w, r, "SAMLResponse.html", FixtureData{})
			default:
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			}
		}))
		defer ts.Close()

		pr := &mocks.Prompter{}
		prompter.SetPrompter(pr)
		pr.Mock.On("StringRequired", "Enter verification code").Return("000000")

		ac, loginDetails := setupTestClient(t, ts)
		got, err := ac.Authenticate(loginDetails)
		require.Nil(t, err)
		require.NotEmpty(t, got)
	})
}

func setupTestClient(t *testing.T, ts *httptest.Server) (Client, *creds.LoginDetails) {
	fixtureData := genFixtureData()
	testTransport := http.DefaultTransport.(*http.Transport).Clone()
	testTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	opts := &provider.HTTPClientOptions{IsWithRetries: false}
	ac := Client{
		client:     &provider.HTTPClient{Client: http.Client{Transport: testTransport}, Options: opts},
		idpAccount: &cfg.IDPAccount{URL: ts.URL, AppID: fixtureData.ApplicationId},
	}
	loginDetails := &creds.LoginDetails{URL: ts.URL, Username: fixtureData.UserName, Password: "test123"}
	return ac, loginDetails
}

func writeFixtureBytes(t *testing.T, w http.ResponseWriter, r *http.Request, templateFile string, variableFixture FixtureData) {
	template, err := template.ParseFiles("testdata/" + templateFile)
	require.Nil(t, err)
	var tpl bytes.Buffer
	err = template.Execute(&tpl, urlFixtures(r.Host, variableFixture))
	require.Nil(t, err)
	_, _ = w.Write(tpl.Bytes())
}

func urlFixtures(host string, urls FixtureData) *FixtureData {
	const scheme = "https://"
	fixtureData := genFixtureData()
	if urls.UrlFederationRedirect != "" {
		fixtureData.UrlFederationRedirect = scheme + host + urls.UrlFederationRedirect
	} else {
		fixtureData.UrlFederationRedirect = ""
	}
	if urls.UrlSkipMfaRegistration != "" {
		fixtureData.UrlSkipMfaRegistration = scheme + host + urls.UrlSkipMfaRegistration
	} else {
		fixtureData.UrlSkipMfaRegistration = ""
	}
	if urls.UrlGetCredentialType != "" {
		fixtureData.UrlGetCredentialType = scheme + host + urls.UrlGetCredentialType
	} else {
		fixtureData.UrlGetCredentialType = ""
	}
	if urls.UrlPost != "" {
		fixtureData.UrlPost = scheme + host + urls.UrlPost
	} else {
		fixtureData.UrlPost = ""
	}
	if urls.UrlBeginAuth != "" {
		fixtureData.UrlBeginAuth = scheme + host + urls.UrlBeginAuth
	} else {
		fixtureData.UrlBeginAuth = ""
	}
	if urls.UrlEndAuth != "" {
		fixtureData.UrlEndAuth = scheme + host + urls.UrlEndAuth
	} else {
		fixtureData.UrlEndAuth = ""
	}
	if urls.UrlProcessAuth != "" {
		fixtureData.UrlProcessAuth = scheme + host + urls.UrlProcessAuth
	} else {
		fixtureData.UrlProcessAuth = ""
	}
	if urls.UrlHiddenForm != "" {
		fixtureData.UrlHiddenForm = scheme + host + urls.UrlHiddenForm
	} else {
		fixtureData.UrlHiddenForm = ""
	}
	if urls.UrlSamlRequest != "" {
		fixtureData.UrlSamlRequest = scheme + host + urls.UrlSamlRequest
	} else {
		fixtureData.UrlSamlRequest = ""
	}
	return fixtureData
}

func genBase64Fixture(length int) string {
	data := make([]byte, length)
	_, _ = crand.Read(data)
	return base64.RawURLEncoding.EncodeToString(data)
}

func genHexFixture(length int) string {
	data := make([]byte, length)
	_, _ = crand.Read(data)
	return hex.EncodeToString(data)
}

func genIntFixture(length int) string {
	low := int(math.Pow(float64(10), float64(length-1)))
	hi := low * 10
	return strconv.Itoa(low + mrand.Intn(hi-low))
}

func genUUID() string {
	return uuid.New().String()
}

func TestAad_UnmarshallMfaResponseWithEntropy(t *testing.T) {

	mfaBeginJsonWithEntropy := []byte("{\"Success\":true,\"ResultValue\":\"Success\",\"Message\":null,\"AuthMethodId\":\"PhoneAppNotification\",\"ErrCode\":0,\"Retry\":false,\"FlowToken\":\"AQABAAEAAAD--DLA3VO7QrddgJg7Wevr5BtzS6C3muY2iOn2W5Nxhyz_B2nFLqOhdxngHgZWDXZHBx6mK27MN6N26J1oz7ydOnsuY3EfEWr5SHToI1N-NpdxotuKfqh6ssxejlKzEaCeYZ1AymWu3DENP9TEo0Pxnd6Vbd7H7soUMjW2-m2ykU1R7bCqcIQiGCF9NX2wmRVm5ia2SzPy1J3rU9nAKnppmiJoyT0yP-U24Jsty7Dje52s-ddFHkjtupiV-R3_JMx4c2KDAfJYabwAWy1Ra1UsxZbSwMkRwhacS46Y9pmztFuSeF6_opIV2H6xNogk2usNnFqJLqT-ibgy2qkJvot07XGH0leN7n-C2oLnziAWpdcC96xracZ16qtTWD6xeBFyM9s-BpHqPfo4Te1a9xlyT3-tlF2qtgUMJSnGN-Ipe21w2pm6mngKL0o1umeyrgz-CXMrGW_sDHUK1D7RqzmZzvh8ZVUBI8bB9os2QFxDypdZfv2qJSTyydJBOM_GDYG_cJ7jcaxonNmSGBDIZTXRlgtzqI3bw43e_NrULuCE2XBj4-nFaNMnEsUfFvSW35po1cLRcDPHoTCUaIdQBU6w0VsuRizMuX7o7y_Nngoc66XNg6XnPtgN0JyQqkyPUPYRRe5pNv7X_9KINtxCitkq5-9PsIIta74GfSehldSJpdI3pi_AhTBHPxtw8caBrySB4PiA7uLC8a3smdYm_cPPeSmsCGRgotRDxooo-FA2hOtCZ52PmlMzjdjmk5719WA_afK9D4MxGt8EmNonI9939XWprUNW2dTc7nQ7asjMo3BonGpP1LfbMIhZ7goD0rGtWNEqIdRifShaFffcKaKcmHtbBeOLWfnUm1PQ-0P0RGHCOh8jMJROn56KjB8djDKHKrvKKjvhVff-P91L_nNVOlqU0GWmWfwhSR279HOtsiQnHVFjnS9Qn0bAjpgf33caLTKebYH6CoUnorCkRHbh44gONFi2rQhOFH_fNKr_Wx6eRlrSj7LZIx20pgSG1RCi4QlVW6fv4Kkk-omRkRwmLrbpdqleoisRMBeyEAKRWk86M2VEyRwIGWakBQbSTkOTb5RENDxwz_VFwcqPkgpuIJzpOoG2p3YhLeqKgEAX5SAA\",\"Ctx\":\"rQQIARAAlVM_rNtEHH5-eQ19iFdQxQITlTohNe_OjtvmQUvjxI7jFzuJ_9tDke1z8P8zthMnGTt1QpW6IbEgxNCxU9XpsXZAFQygjkwsSNCpI46eSiW2fsN3p7vvvt_d6ft92oIdeHIVnMO7tuNz8l7PXqO4_O4H3dnVn27_cJf_Tv3494u3u48fETCoqrw8OT52PA8vs6rjeFW48lFY-F6Fi02nDjOE69LZLgu_4-H0-AlBPCeIPwni0f4VeJ2mAN27AUHHD7FIYjh2y_7SO53Lk6FUreoX--9P-8sqIHeEi3Drv9w_XOAi_TLHZfVt65eDae5nYzTAWdYU7OxkflaFnlOFOJsVOPeLKvTLW_15v8F4R8IkExJ7lGxsQwJf1xxGvFx7W7yakFxkkT3oZvOl1ew5pv2fzqUEepKh3E3lFaKkpoi-sRU6ckmwskymdkdJZJly7pL0dkK98UejXmobcuKlHGjGwOOZ0jGkAI2SlRvSgUcx3Rno1bYpnK9FUHQMumi0qmOgpWJ00__5C_YQJhLJrkVVDsUBqKXoK2qizqE9YitLTSJ7AGhbtWp7aG3EVIhENfZVikncOInnZG_ppnqEBvTQJeVkkry5q24Ked3ncknnZvZwTJmwRyN-Dnx2zaNEMjUgBCZIFs15WuN6Y2Wrx1rEUiJkMlXXZ_MUGSpLQ9FAhpfWXZTStk6i0gE24xqcLupspUNOUVR5qIIxcGMp1kA-mPLc1tM5Rlb7azEOVlImF1Mt3vp6482zW1XDUB2tTzUFxo4GIztBoQP0yjVtSklRYRmwMIGwsMB6MM-CBTLygToSKIVPplOegSLFGZpqF3LzVjHRFTkWu7qOlCkrK82_VBIMxlaiizaLIpPsPm61m5ymOHvWutTkJwvRJ3mBF2Hi_9H6CKVO4eGq8u-UvtdEusZFXO5y_fyAeHVAfH-h6ZLffvzwn4eff3bn4eLo3rXelb1nF44nqAzimyMLlxq8Xhr0jQimclY4mInJGZLcmXczq91TU3LFW9QJfNAmHrTbf7f3779DPD18-x67997Rxb3Lh4fK5ov75ckL_uxo79WlX5-enT35-Zu_-H8B0\",\"SessionId\":\"21036f6c-f348-4396-ae7b-2afaf476eb29\",\"CorrelationId\":\"c1245034-a43e-485e-9d54-1ad8083e34b2\",\"Timestamp\":\"2022-05-20T15:15:11Z\",\"Entropy\":88}")
	var mfaResp mfaResponse

	if err := json.Unmarshal(mfaBeginJsonWithEntropy, &mfaResp); err != nil {
		t.Error("Found an error while unmarshalling")
	}

	if mfaResp.Entropy != 88 {
		t.Errorf("Entropy is %d and should have been 88", mfaResp.Entropy)
	}
}

func TestAad_UnmarshallMfaResponseWithoutEntropy(t *testing.T) {

	mfaBeginJsonWithEntropy := []byte("{\"Success\":true,\"ResultValue\":\"Success\",\"Message\":null,\"AuthMethodId\":\"PhoneAppNotification\",\"ErrCode\":0,\"Retry\":false,\"FlowToken\":\"AQABAAEAAAD--DLA3VO7QrddgJg7Wevr5BtzS6C3muY2iOn2W5Nxhyz_B2nFLqOhdxngHgZWDXZHBx6mK27MN6N26J1oz7ydOnsuY3EfEWr5SHToI1N-NpdxotuKfqh6ssxejlKzEaCeYZ1AymWu3DENP9TEo0Pxnd6Vbd7H7soUMjW2-m2ykU1R7bCqcIQiGCF9NX2wmRVm5ia2SzPy1J3rU9nAKnppmiJoyT0yP-U24Jsty7Dje52s-ddFHkjtupiV-R3_JMx4c2KDAfJYabwAWy1Ra1UsxZbSwMkRwhacS46Y9pmztFuSeF6_opIV2H6xNogk2usNnFqJLqT-ibgy2qkJvot07XGH0leN7n-C2oLnziAWpdcC96xracZ16qtTWD6xeBFyM9s-BpHqPfo4Te1a9xlyT3-tlF2qtgUMJSnGN-Ipe21w2pm6mngKL0o1umeyrgz-CXMrGW_sDHUK1D7RqzmZzvh8ZVUBI8bB9os2QFxDypdZfv2qJSTyydJBOM_GDYG_cJ7jcaxonNmSGBDIZTXRlgtzqI3bw43e_NrULuCE2XBj4-nFaNMnEsUfFvSW35po1cLRcDPHoTCUaIdQBU6w0VsuRizMuX7o7y_Nngoc66XNg6XnPtgN0JyQqkyPUPYRRe5pNv7X_9KINtxCitkq5-9PsIIta74GfSehldSJpdI3pi_AhTBHPxtw8caBrySB4PiA7uLC8a3smdYm_cPPeSmsCGRgotRDxooo-FA2hOtCZ52PmlMzjdjmk5719WA_afK9D4MxGt8EmNonI9939XWprUNW2dTc7nQ7asjMo3BonGpP1LfbMIhZ7goD0rGtWNEqIdRifShaFffcKaKcmHtbBeOLWfnUm1PQ-0P0RGHCOh8jMJROn56KjB8djDKHKrvKKjvhVff-P91L_nNVOlqU0GWmWfwhSR279HOtsiQnHVFjnS9Qn0bAjpgf33caLTKebYH6CoUnorCkRHbh44gONFi2rQhOFH_fNKr_Wx6eRlrSj7LZIx20pgSG1RCi4QlVW6fv4Kkk-omRkRwmLrbpdqleoisRMBeyEAKRWk86M2VEyRwIGWakBQbSTkOTb5RENDxwz_VFwcqPkgpuIJzpOoG2p3YhLeqKgEAX5SAA\",\"Ctx\":\"rQQIARAAlVM_rNtEHH5-eQ19iFdQxQITlTohNe_OjtvmQUvjxI7jFzuJ_9tDke1z8P8zthMnGTt1QpW6IbEgxNCxU9XpsXZAFQygjkwsSNCpI46eSiW2fsN3p7vvvt_d6ft92oIdeHIVnMO7tuNz8l7PXqO4_O4H3dnVn27_cJf_Tv3494u3u48fETCoqrw8OT52PA8vs6rjeFW48lFY-F6Fi02nDjOE69LZLgu_4-H0-AlBPCeIPwni0f4VeJ2mAN27AUHHD7FIYjh2y_7SO53Lk6FUreoX--9P-8sqIHeEi3Drv9w_XOAi_TLHZfVt65eDae5nYzTAWdYU7OxkflaFnlOFOJsVOPeLKvTLW_15v8F4R8IkExJ7lGxsQwJf1xxGvFx7W7yakFxkkT3oZvOl1ew5pv2fzqUEepKh3E3lFaKkpoi-sRU6ckmwskymdkdJZJly7pL0dkK98UejXmobcuKlHGjGwOOZ0jGkAI2SlRvSgUcx3Rno1bYpnK9FUHQMumi0qmOgpWJ00__5C_YQJhLJrkVVDsUBqKXoK2qizqE9YitLTSJ7AGhbtWp7aG3EVIhENfZVikncOInnZG_ppnqEBvTQJeVkkry5q24Ked3ncknnZvZwTJmwRyN-Dnx2zaNEMjUgBCZIFs15WuN6Y2Wrx1rEUiJkMlXXZ_MUGSpLQ9FAhpfWXZTStk6i0gE24xqcLupspUNOUVR5qIIxcGMp1kA-mPLc1tM5Rlb7azEOVlImF1Mt3vp6482zW1XDUB2tTzUFxo4GIztBoQP0yjVtSklRYRmwMIGwsMB6MM-CBTLygToSKIVPplOegSLFGZpqF3LzVjHRFTkWu7qOlCkrK82_VBIMxlaiizaLIpPsPm61m5ymOHvWutTkJwvRJ3mBF2Hi_9H6CKVO4eGq8u-UvtdEusZFXO5y_fyAeHVAfH-h6ZLffvzwn4eff3bn4eLo3rXelb1nF44nqAzimyMLlxq8Xhr0jQimclY4mInJGZLcmXczq91TU3LFW9QJfNAmHrTbf7f3779DPD18-x67997Rxb3Lh4fK5ov75ckL_uxo79WlX5-enT35-Zu_-H8B0\",\"SessionId\":\"21036f6c-f348-4396-ae7b-2afaf476eb29\",\"CorrelationId\":\"c1245034-a43e-485e-9d54-1ad8083e34b2\",\"Timestamp\":\"2022-05-20T15:15:11Z\"}")
	var mfaResp mfaResponse

	if err := json.Unmarshal(mfaBeginJsonWithEntropy, &mfaResp); err != nil {
		t.Error("Found an error while unmarshalling")
	}

	if mfaResp.Entropy != 0 {
		t.Errorf("Entropy is %d and should have been 0", mfaResp.Entropy)
	}
}
