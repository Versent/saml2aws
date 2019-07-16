package aad

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
)

var logger = logrus.WithField("provider", "aad")

// Client wrapper around AzureAD enabling authentication and retrieval of assertions
type Client struct {
	client     *provider.HTTPClient
	idpAccount *cfg.IDPAccount
}

// Autogenerate startSAML Response struct
// some case, some fiels is not exists
type startSAMLResponse struct {
	FShowPersistentCookiesWarning         bool     `json:"fShowPersistentCookiesWarning"`
	URLMsaLogout                          string   `json:"urlMsaLogout"`
	ShowCantAccessAccountLink             bool     `json:"showCantAccessAccountLink"`
	URLGitHubFed                          string   `json:"urlGitHubFed"`
	FShowSignInWithGitHubOnlyOnCredPicker bool     `json:"fShowSignInWithGitHubOnlyOnCredPicker"`
	FEnableShowResendCode                 bool     `json:"fEnableShowResendCode"`
	IShowResendCodeDelay                  int      `json:"iShowResendCodeDelay"`
	SSMSCtryPhoneData                     string   `json:"sSMSCtryPhoneData"`
	FUseInlinePhoneNumber                 bool     `json:"fUseInlinePhoneNumber"`
	URLSessionState                       string   `json:"urlSessionState"`
	URLResetPassword                      string   `json:"urlResetPassword"`
	URLMsaResetPassword                   string   `json:"urlMsaResetPassword"`
	URLLogin                              string   `json:"urlLogin"`
	URLSignUp                             string   `json:"urlSignUp"`
	URLGetCredentialType                  string   `json:"urlGetCredentialType"`
	URLGetOneTimeCode                     string   `json:"urlGetOneTimeCode"`
	URLLogout                             string   `json:"urlLogout"`
	URLForget                             string   `json:"urlForget"`
	URLDisambigRename                     string   `json:"urlDisambigRename"`
	URLGoToAADError                       string   `json:"urlGoToAADError"`
	URLDssoStatus                         string   `json:"urlDssoStatus"`
	URLFidoHelp                           string   `json:"urlFidoHelp"`
	URLFidoLogin                          string   `json:"urlFidoLogin"`
	URLPostAad                            string   `json:"urlPostAad"`
	URLPostMsa                            string   `json:"urlPostMsa"`
	URLPIAEndAuth                         string   `json:"urlPIAEndAuth"`
	FCBShowSignUp                         bool     `json:"fCBShowSignUp"`
	FKMSIEnabled                          bool     `json:"fKMSIEnabled"`
	ILoginMode                            int      `json:"iLoginMode"`
	FAllowPhoneSignIn                     bool     `json:"fAllowPhoneSignIn"`
	FAllowPhoneInput                      bool     `json:"fAllowPhoneInput"`
	FAllowSkypeNameLogin                  bool     `json:"fAllowSkypeNameLogin"`
	IMaxPollErrors                        int      `json:"iMaxPollErrors"`
	IPollingTimeout                       int      `json:"iPollingTimeout"`
	SrsSuccess                            bool     `json:"srsSuccess"`
	FShowSwitchUser                       bool     `json:"fShowSwitchUser"`
	ArrValErrs                            []string `json:"arrValErrs"`
	SErrorCode                            string   `json:"sErrorCode"`
	SErrTxt                               string   `json:"sErrTxt"`
	SResetPasswordPrefillParam            string   `json:"sResetPasswordPrefillParam"`
	OnPremPasswordValidationConfig        struct {
		IsUserRealmPrecheckEnabled bool `json:"isUserRealmPrecheckEnabled"`
	} `json:"onPremPasswordValidationConfig"`
	FSwitchDisambig   bool `json:"fSwitchDisambig"`
	OCancelPostParams struct {
		Error        string `json:"error"`
		ErrorSubcode string `json:"error_subcode"`
		State        string `json:"state"`
	} `json:"oCancelPostParams"`
	IAllowedIdentities                  int         `json:"iAllowedIdentities"`
	IRemoteNgcPollingType               int         `json:"iRemoteNgcPollingType"`
	IsGlobalTenant                      bool        `json:"isGlobalTenant"`
	FIsFidoSupported                    bool        `json:"fIsFidoSupported"`
	FUseNewNoPasswordTypes              bool        `json:"fUseNewNoPasswordTypes"`
	IMaxStackForKnockoutAsyncComponents int         `json:"iMaxStackForKnockoutAsyncComponents"`
	StrCopyrightTxt                     string      `json:"strCopyrightTxt"`
	FShowButtons                        bool        `json:"fShowButtons"`
	URLCdn                              string      `json:"urlCdn"`
	URLFooterTOU                        string      `json:"urlFooterTOU"`
	URLFooterPrivacy                    string      `json:"urlFooterPrivacy"`
	URLPost                             string      `json:"urlPost"`
	URLRefresh                          string      `json:"urlRefresh"`
	URLCancel                           string      `json:"urlCancel"`
	IPawnIcon                           int         `json:"iPawnIcon"`
	IPollingInterval                    int         `json:"iPollingInterval"`
	SPOSTUsername                       string      `json:"sPOST_Username"`
	SFT                                 string      `json:"sFT"`
	SFTName                             string      `json:"sFTName"`
	SSessionIdentifierName              string      `json:"sSessionIdentifierName"`
	SCtx                                string      `json:"sCtx"`
	IProductIcon                        int         `json:"iProductIcon"`
	URLReportPageLoad                   string      `json:"urlReportPageLoad"`
	StaticTenantBranding                interface{} `json:"staticTenantBranding"`
	OAppCobranding                      struct {
	} `json:"oAppCobranding"`
	IBackgroundImage                      int           `json:"iBackgroundImage"`
	ArrSessions                           []interface{} `json:"arrSessions"`
	FUseConstantPolling                   bool          `json:"fUseConstantPolling"`
	FUseFlowTokenAsCanary                 bool          `json:"fUseFlowTokenAsCanary"`
	FApplicationInsightsEnabled           bool          `json:"fApplicationInsightsEnabled"`
	IApplicationInsightsEnabledPercentage int           `json:"iApplicationInsightsEnabledPercentage"`
	URLSetDebugMode                       string        `json:"urlSetDebugMode"`
	FEnableCSSAnimation                   bool          `json:"fEnableCssAnimation"`
	FAllowGrayOutLightBox                 bool          `json:"fAllowGrayOutLightBox"`
	FIsRemoteNGCSupported                 bool          `json:"fIsRemoteNGCSupported"`
	Scid                                  int           `json:"scid"`
	Hpgact                                int           `json:"hpgact"`
	Hpgid                                 int           `json:"hpgid"`
	Pgid                                  string        `json:"pgid"`
	APICanary                             string        `json:"apiCanary"`
	Canary                                string        `json:"canary"`
	CorrelationID                         string        `json:"correlationId"`
	SessionID                             string        `json:"sessionId"`
	Locale                                struct {
		Mkt  string `json:"mkt"`
		Lcid int    `json:"lcid"`
	} `json:"locale"`
	SlMaxRetry      int  `json:"slMaxRetry"`
	SlReportFailure bool `json:"slReportFailure"`
	Strings         struct {
		Desktopsso struct {
			Authenticatingmessage string `json:"authenticatingmessage"`
		} `json:"desktopsso"`
	} `json:"strings"`
	Enums struct {
		ClientMetricsModes struct {
			None             int `json:"None"`
			SubmitOnPost     int `json:"SubmitOnPost"`
			SubmitOnRedirect int `json:"SubmitOnRedirect"`
			InstrumentPlt    int `json:"InstrumentPlt"`
		} `json:"ClientMetricsModes"`
	} `json:"enums"`
	Urls struct {
		Instr struct {
			Pageload   string `json:"pageload"`
			Dssostatus string `json:"dssostatus"`
		} `json:"instr"`
	} `json:"urls"`
	Browser struct {
		Ltr     int `json:"ltr"`
		Other   int `json:"_Other"`
		Full    int `json:"Full"`
		REOther int `json:"RE_Other"`
		B       struct {
			Name  string `json:"name"`
			Major int    `json:"major"`
			Minor int    `json:"minor"`
		} `json:"b"`
		Os struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"os"`
		V int `json:"V"`
	} `json:"browser"`
	Watson struct {
		URL              string   `json:"url"`
		Bundle           string   `json:"bundle"`
		Sbundle          string   `json:"sbundle"`
		Fbundle          string   `json:"fbundle"`
		ResetErrorPeriod int      `json:"resetErrorPeriod"`
		MaxCorsErrors    int      `json:"maxCorsErrors"`
		MaxInjectErrors  int      `json:"maxInjectErrors"`
		MaxErrors        int      `json:"maxErrors"`
		MaxTotalErrors   int      `json:"maxTotalErrors"`
		ExpSrcs          []string `json:"expSrcs"`
		EnvErrorRedirect bool     `json:"envErrorRedirect"`
		EnvErrorURL      string   `json:"envErrorUrl"`
	} `json:"watson"`
	Loader struct {
		CdnRoots []string `json:"cdnRoots"`
	} `json:"loader"`
	ServerDetails struct {
		Slc string `json:"slc"`
		Dc  string `json:"dc"`
		Ri  string `json:"ri"`
		Ver struct {
			V []int `json:"v"`
		} `json:"ver"`
		Rt string `json:"rt"`
		Et int    `json:"et"`
	} `json:"serverDetails"`
	Country                    string `json:"country"`
	FBreakBrandingSigninString bool   `json:"fBreakBrandingSigninString"`
	Bsso                       struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	} `json:"bsso"`
	URLNoCookies       string `json:"urlNoCookies"`
	FTrimChromeBssoURL bool   `json:"fTrimChromeBssoUrl"`
}

// Autogenerate password login response
// some case, some fiels is not exists
type passwordLoginResponse struct {
	ArrUserProofs []struct {
		AuthMethodID string `json:"authMethodId"`
		Data         string `json:"data"`
		Display      string `json:"display"`
		IsDefault    bool   `json:"isDefault"`
	} `json:"arrUserProofs"`
	FHideIHaveCodeLink                  bool               `json:"fHideIHaveCodeLink"`
	OPerAuthPollingInterval             map[string]float64 `json:"oPerAuthPollingInterval"`
	FProofIndexedByType                 bool               `json:"fProofIndexedByType"`
	URLBeginAuth                        string             `json:"urlBeginAuth"`
	URLEndAuth                          string             `json:"urlEndAuth"`
	ISAMode                             int                `json:"iSAMode"`
	ITrustedDeviceCheckboxConfig        int                `json:"iTrustedDeviceCheckboxConfig"`
	IMaxPollAttempts                    int                `json:"iMaxPollAttempts"`
	IPollingTimeout                     int                `json:"iPollingTimeout"`
	IPollingBackoffInterval             float64            `json:"iPollingBackoffInterval"`
	IRememberMfaDuration                float64            `json:"iRememberMfaDuration"`
	STrustedDeviceCheckboxName          string             `json:"sTrustedDeviceCheckboxName"`
	SAuthMethodInputFieldName           string             `json:"sAuthMethodInputFieldName"`
	ISAOtcLength                        int                `json:"iSAOtcLength"`
	ITotpOtcLength                      int                `json:"iTotpOtcLength"`
	URLMoreInfo                         string             `json:"urlMoreInfo"`
	FShowViewDetailsLink                bool               `json:"fShowViewDetailsLink"`
	FAlwaysUpdateFTInSasEnd             bool               `json:"fAlwaysUpdateFTInSasEnd"`
	IMaxStackForKnockoutAsyncComponents int                `json:"iMaxStackForKnockoutAsyncComponents"`
	StrCopyrightTxt                     string             `json:"strCopyrightTxt"`
	FShowButtons                        bool               `json:"fShowButtons"`
	URLCdn                              string             `json:"urlCdn"`
	URLFooterTOU                        string             `json:"urlFooterTOU"`
	URLFooterPrivacy                    string             `json:"urlFooterPrivacy"`
	URLPost                             string             `json:"urlPost"`
	URLCancel                           string             `json:"urlCancel"`
	IPawnIcon                           int                `json:"iPawnIcon"`
	IPollingInterval                    int                `json:"iPollingInterval"`
	SPOSTUsername                       string             `json:"sPOST_Username"`
	SFT                                 string             `json:"sFT"`
	SFTName                             string             `json:"sFTName"`
	SCtx                                string             `json:"sCtx"`
	DynamicTenantBranding               []struct {
		Locale                 int    `json:"Locale"`
		Illustration           string `json:"Illustration"`
		UserIDLabel            string `json:"UserIdLabel"`
		KeepMeSignedInDisabled bool   `json:"KeepMeSignedInDisabled"`
		UseTransparentLightBox bool   `json:"UseTransparentLightBox"`
	} `json:"dynamicTenantBranding"`
	OAppCobranding struct {
	} `json:"oAppCobranding"`
	IBackgroundImage                      int    `json:"iBackgroundImage"`
	FUseConstantPolling                   bool   `json:"fUseConstantPolling"`
	FUseFlowTokenAsCanary                 bool   `json:"fUseFlowTokenAsCanary"`
	FApplicationInsightsEnabled           bool   `json:"fApplicationInsightsEnabled"`
	IApplicationInsightsEnabledPercentage int    `json:"iApplicationInsightsEnabledPercentage"`
	URLSetDebugMode                       string `json:"urlSetDebugMode"`
	FEnableCSSAnimation                   bool   `json:"fEnableCssAnimation"`
	FAllowGrayOutLightBox                 bool   `json:"fAllowGrayOutLightBox"`
	FIsRemoteNGCSupported                 bool   `json:"fIsRemoteNGCSupported"`
	Scid                                  int    `json:"scid"`
	Hpgact                                int    `json:"hpgact"`
	Hpgid                                 int    `json:"hpgid"`
	Pgid                                  string `json:"pgid"`
	APICanary                             string `json:"apiCanary"`
	Canary                                string `json:"canary"`
	CorrelationID                         string `json:"correlationId"`
	SessionID                             string `json:"sessionId"`
	Locale                                struct {
		Mkt  string `json:"mkt"`
		Lcid int    `json:"lcid"`
	} `json:"locale"`
	SlMaxRetry      int  `json:"slMaxRetry"`
	SlReportFailure bool `json:"slReportFailure"`
	Strings         struct {
		Desktopsso struct {
			Authenticatingmessage string `json:"authenticatingmessage"`
		} `json:"desktopsso"`
	} `json:"strings"`
	Enums struct {
		ClientMetricsModes struct {
			None             int `json:"None"`
			SubmitOnPost     int `json:"SubmitOnPost"`
			SubmitOnRedirect int `json:"SubmitOnRedirect"`
			InstrumentPlt    int `json:"InstrumentPlt"`
		} `json:"ClientMetricsModes"`
	} `json:"enums"`
	Urls struct {
		Instr struct {
			Pageload   string `json:"pageload"`
			Dssostatus string `json:"dssostatus"`
		} `json:"instr"`
	} `json:"urls"`
	Browser struct {
		Ltr     int `json:"ltr"`
		Other   int `json:"_Other"`
		Full    int `json:"Full"`
		REOther int `json:"RE_Other"`
		B       struct {
			Name  string `json:"name"`
			Major int    `json:"major"`
			Minor int    `json:"minor"`
		} `json:"b"`
		Os struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"os"`
		V int `json:"V"`
	} `json:"browser"`
	Watson struct {
		URL              string   `json:"url"`
		Bundle           string   `json:"bundle"`
		Sbundle          string   `json:"sbundle"`
		Fbundle          string   `json:"fbundle"`
		ResetErrorPeriod int      `json:"resetErrorPeriod"`
		MaxCorsErrors    int      `json:"maxCorsErrors"`
		MaxInjectErrors  int      `json:"maxInjectErrors"`
		MaxErrors        int      `json:"maxErrors"`
		MaxTotalErrors   int      `json:"maxTotalErrors"`
		ExpSrcs          []string `json:"expSrcs"`
		EnvErrorRedirect bool     `json:"envErrorRedirect"`
		EnvErrorURL      string   `json:"envErrorUrl"`
	} `json:"watson"`
	Loader struct {
		CdnRoots []string `json:"cdnRoots"`
	} `json:"loader"`
	ServerDetails struct {
		Slc string `json:"slc"`
		Dc  string `json:"dc"`
		Ri  string `json:"ri"`
		Ver struct {
			V []int `json:"v"`
		} `json:"ver"`
		Rt string `json:"rt"`
		Et int    `json:"et"`
	} `json:"serverDetails"`
	Country                    string `json:"country"`
	FBreakBrandingSigninString bool   `json:"fBreakBrandingSigninString"`
	URLNoCookies               string `json:"urlNoCookies"`
	FTrimChromeBssoURL         bool   `json:"fTrimChromeBssoUrl"`
}

// Autogenerated skip mfa login response
type SkipMfaResponse struct {
	URLPostRedirect                     string `json:"urlPostRedirect"`
	URLSkipMfaRegistration              string `json:"urlSkipMfaRegistration"`
	URLMoreInfo                         string `json:"urlMoreInfo"`
	SProofUpToken                       string `json:"sProofUpToken"`
	SProofUpTokenName                   string `json:"sProofUpTokenName"`
	SProofUpAuthState                   string `json:"sProofUpAuthState"`
	SCanaryToken                        string `json:"sCanaryToken"`
	IRemainingDaysToSkipMfaRegistration int    `json:"iRemainingDaysToSkipMfaRegistration"`
	IMaxStackForKnockoutAsyncComponents int    `json:"iMaxStackForKnockoutAsyncComponents"`
	StrCopyrightTxt                     string `json:"strCopyrightTxt"`
	FShowButtons                        bool   `json:"fShowButtons"`
	URLCdn                              string `json:"urlCdn"`
	URLFooterTOU                        string `json:"urlFooterTOU"`
	URLFooterPrivacy                    string `json:"urlFooterPrivacy"`
	URLPost                             string `json:"urlPost"`
	URLCancel                           string `json:"urlCancel"`
	IPawnIcon                           int    `json:"iPawnIcon"`
	SPOSTUsername                       string `json:"sPOST_Username"`
	SFT                                 string `json:"sFT"`
	SFTName                             string `json:"sFTName"`
	SCanaryTokenName                    string `json:"sCanaryTokenName"`
	DynamicTenantBranding               []struct {
		Locale                 int    `json:"Locale"`
		Illustration           string `json:"Illustration"`
		UserIDLabel            string `json:"UserIdLabel"`
		KeepMeSignedInDisabled bool   `json:"KeepMeSignedInDisabled"`
		UseTransparentLightBox bool   `json:"UseTransparentLightBox"`
	} `json:"dynamicTenantBranding"`
	OAppCobranding struct {
	} `json:"oAppCobranding"`
	IBackgroundImage                      int    `json:"iBackgroundImage"`
	FUseConstantPolling                   bool   `json:"fUseConstantPolling"`
	FUseFlowTokenAsCanary                 bool   `json:"fUseFlowTokenAsCanary"`
	FApplicationInsightsEnabled           bool   `json:"fApplicationInsightsEnabled"`
	IApplicationInsightsEnabledPercentage int    `json:"iApplicationInsightsEnabledPercentage"`
	URLSetDebugMode                       string `json:"urlSetDebugMode"`
	FEnableCSSAnimation                   bool   `json:"fEnableCssAnimation"`
	FAllowGrayOutLightBox                 bool   `json:"fAllowGrayOutLightBox"`
	FIsRemoteNGCSupported                 bool   `json:"fIsRemoteNGCSupported"`
	Scid                                  int    `json:"scid"`
	Hpgact                                int    `json:"hpgact"`
	Hpgid                                 int    `json:"hpgid"`
	Pgid                                  string `json:"pgid"`
	APICanary                             string `json:"apiCanary"`
	Canary                                string `json:"canary"`
	CorrelationID                         string `json:"correlationId"`
	SessionID                             string `json:"sessionId"`
	Locale                                struct {
		Mkt  string `json:"mkt"`
		Lcid int    `json:"lcid"`
	} `json:"locale"`
	SlMaxRetry      int  `json:"slMaxRetry"`
	SlReportFailure bool `json:"slReportFailure"`
	Strings         struct {
		Desktopsso struct {
			Authenticatingmessage string `json:"authenticatingmessage"`
		} `json:"desktopsso"`
	} `json:"strings"`
	Enums struct {
		ClientMetricsModes struct {
			None             int `json:"None"`
			SubmitOnPost     int `json:"SubmitOnPost"`
			SubmitOnRedirect int `json:"SubmitOnRedirect"`
			InstrumentPlt    int `json:"InstrumentPlt"`
		} `json:"ClientMetricsModes"`
	} `json:"enums"`
	Urls struct {
		Instr struct {
			Pageload   string `json:"pageload"`
			Dssostatus string `json:"dssostatus"`
		} `json:"instr"`
	} `json:"urls"`
	Browser struct {
		Ltr     int `json:"ltr"`
		Other   int `json:"_Other"`
		Full    int `json:"Full"`
		REOther int `json:"RE_Other"`
		B       struct {
			Name  string `json:"name"`
			Major int    `json:"major"`
			Minor int    `json:"minor"`
		} `json:"b"`
		Os struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"os"`
		V int `json:"V"`
	} `json:"browser"`
	Watson struct {
		URL              string   `json:"url"`
		Bundle           string   `json:"bundle"`
		Sbundle          string   `json:"sbundle"`
		Fbundle          string   `json:"fbundle"`
		ResetErrorPeriod int      `json:"resetErrorPeriod"`
		MaxCorsErrors    int      `json:"maxCorsErrors"`
		MaxInjectErrors  int      `json:"maxInjectErrors"`
		MaxErrors        int      `json:"maxErrors"`
		MaxTotalErrors   int      `json:"maxTotalErrors"`
		ExpSrcs          []string `json:"expSrcs"`
		EnvErrorRedirect bool     `json:"envErrorRedirect"`
		EnvErrorURL      string   `json:"envErrorUrl"`
	} `json:"watson"`
	Loader struct {
		CdnRoots []string `json:"cdnRoots"`
	} `json:"loader"`
	ServerDetails struct {
		Slc string `json:"slc"`
		Dc  string `json:"dc"`
		Ri  string `json:"ri"`
		Ver struct {
			V []int `json:"v"`
		} `json:"ver"`
		Rt string `json:"rt"`
		Et int    `json:"et"`
	} `json:"serverDetails"`
	Country                    string `json:"country"`
	FBreakBrandingSigninString bool   `json:"fBreakBrandingSigninString"`
	URLNoCookies               string `json:"urlNoCookies"`
	FTrimChromeBssoURL         bool   `json:"fTrimChromeBssoUrl"`
}

// mfa request
type mfaRequest struct {
	AuthMethodID       string `json:"AuthMethodId"`
	Method             string `json:"Method"`
	Ctx                string `json:"Ctx"`
	FlowToken          string `json:"FlowToken"`
	SessionID          string `json:"SessionId,omitempty"`
	AdditionalAuthData string `json:"AdditionalAuthData,omitempty"`
}

// mfa response
type mfaResponse struct {
	Success       bool        `json:"Success"`
	ResultValue   string      `json:"ResultValue"`
	Message       interface{} `json:"Message"`
	AuthMethodID  string      `json:"AuthMethodId"`
	ErrCode       int         `json:"ErrCode"`
	Retry         bool        `json:"Retry"`
	FlowToken     string      `json:"FlowToken"`
	Ctx           string      `json:"Ctx"`
	SessionID     string      `json:"SessionId"`
	CorrelationID string      `json:"CorrelationId"`
	Timestamp     time.Time   `json:"Timestamp"`
}

// Autogenerate ProcessAuth response
// some case, some fiels is not exists
type processAuthResponse struct {
	IMaxStackForKnockoutAsyncComponents int    `json:"iMaxStackForKnockoutAsyncComponents"`
	StrCopyrightTxt                     string `json:"strCopyrightTxt"`
	FShowButtons                        bool   `json:"fShowButtons"`
	URLCdn                              string `json:"urlCdn"`
	URLFooterTOU                        string `json:"urlFooterTOU"`
	URLFooterPrivacy                    string `json:"urlFooterPrivacy"`
	URLPost                             string `json:"urlPost"`
	IPawnIcon                           int    `json:"iPawnIcon"`
	SPOSTUsername                       string `json:"sPOST_Username"`
	SFT                                 string `json:"sFT"`
	SFTName                             string `json:"sFTName"`
	SCtx                                string `json:"sCtx"`
	SCanaryTokenName                    string `json:"sCanaryTokenName"`
	DynamicTenantBranding               []struct {
		Locale                 int    `json:"Locale"`
		Illustration           string `json:"Illustration"`
		UserIDLabel            string `json:"UserIdLabel"`
		KeepMeSignedInDisabled bool   `json:"KeepMeSignedInDisabled"`
		UseTransparentLightBox bool   `json:"UseTransparentLightBox"`
	} `json:"dynamicTenantBranding"`
	OAppCobranding struct {
	} `json:"oAppCobranding"`
	IBackgroundImage                      int    `json:"iBackgroundImage"`
	FUseConstantPolling                   bool   `json:"fUseConstantPolling"`
	FUseFlowTokenAsCanary                 bool   `json:"fUseFlowTokenAsCanary"`
	FApplicationInsightsEnabled           bool   `json:"fApplicationInsightsEnabled"`
	IApplicationInsightsEnabledPercentage int    `json:"iApplicationInsightsEnabledPercentage"`
	URLSetDebugMode                       string `json:"urlSetDebugMode"`
	FEnableCSSAnimation                   bool   `json:"fEnableCssAnimation"`
	FAllowGrayOutLightBox                 bool   `json:"fAllowGrayOutLightBox"`
	FIsRemoteNGCSupported                 bool   `json:"fIsRemoteNGCSupported"`
	Scid                                  int    `json:"scid"`
	Hpgact                                int    `json:"hpgact"`
	Hpgid                                 int    `json:"hpgid"`
	Pgid                                  string `json:"pgid"`
	APICanary                             string `json:"apiCanary"`
	Canary                                string `json:"canary"`
	CorrelationID                         string `json:"correlationId"`
	SessionID                             string `json:"sessionId"`
	Locale                                struct {
		Mkt  string `json:"mkt"`
		Lcid int    `json:"lcid"`
	} `json:"locale"`
	SlMaxRetry      int  `json:"slMaxRetry"`
	SlReportFailure bool `json:"slReportFailure"`
	Strings         struct {
		Desktopsso struct {
			Authenticatingmessage string `json:"authenticatingmessage"`
		} `json:"desktopsso"`
	} `json:"strings"`
	Enums struct {
		ClientMetricsModes struct {
			None             int `json:"None"`
			SubmitOnPost     int `json:"SubmitOnPost"`
			SubmitOnRedirect int `json:"SubmitOnRedirect"`
			InstrumentPlt    int `json:"InstrumentPlt"`
		} `json:"ClientMetricsModes"`
	} `json:"enums"`
	Urls struct {
		Instr struct {
			Pageload   string `json:"pageload"`
			Dssostatus string `json:"dssostatus"`
		} `json:"instr"`
	} `json:"urls"`
	Browser struct {
		Ltr     int `json:"ltr"`
		Other   int `json:"_Other"`
		Full    int `json:"Full"`
		REOther int `json:"RE_Other"`
		B       struct {
			Name  string `json:"name"`
			Major int    `json:"major"`
			Minor int    `json:"minor"`
		} `json:"b"`
		Os struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"os"`
		V int `json:"V"`
	} `json:"browser"`
	Watson struct {
		URL              string   `json:"url"`
		Bundle           string   `json:"bundle"`
		Sbundle          string   `json:"sbundle"`
		Fbundle          string   `json:"fbundle"`
		ResetErrorPeriod int      `json:"resetErrorPeriod"`
		MaxCorsErrors    int      `json:"maxCorsErrors"`
		MaxInjectErrors  int      `json:"maxInjectErrors"`
		MaxErrors        int      `json:"maxErrors"`
		MaxTotalErrors   int      `json:"maxTotalErrors"`
		ExpSrcs          []string `json:"expSrcs"`
		EnvErrorRedirect bool     `json:"envErrorRedirect"`
		EnvErrorURL      string   `json:"envErrorUrl"`
	} `json:"watson"`
	Loader struct {
		CdnRoots []string `json:"cdnRoots"`
	} `json:"loader"`
	ServerDetails struct {
		Slc string `json:"slc"`
		Dc  string `json:"dc"`
		Ri  string `json:"ri"`
		Ver struct {
			V []int `json:"v"`
		} `json:"ver"`
		Rt string `json:"rt"`
		Et int    `json:"et"`
	} `json:"serverDetails"`
	Country                    string `json:"country"`
	FBreakBrandingSigninString bool   `json:"fBreakBrandingSigninString"`
	URLNoCookies               string `json:"urlNoCookies"`
	FTrimChromeBssoURL         bool   `json:"fTrimChromeBssoUrl"`
}

// New create a new AzureAD client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: idpAccount.SkipVerify, Renegotiation: tls.RenegotiateFreelyAsClient},
	}

	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	return &Client{
		client:     client,
		idpAccount: idpAccount,
	}, nil
}

// Authenticate to AzureAD and return the data from the body of the SAML assertion.
func (ac *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	var samlAssertion string
	var res *http.Response

	// idpAccount.URL = https://account.activedirectory.windowsazure.com

	// startSAML
	startURL := fmt.Sprintf("%s/applications/redirecttofederatedapplication.aspx?Operation=LinkedSignIn&applicationId=%s", ac.idpAccount.URL, ac.idpAccount.AppID)

	res, err := ac.client.Get(startURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving form")
	}

	// data is embeded javascript object
	// <script><![CDATA[  $Config=......; ]]>
	scanner := bufio.NewScanner(res.Body)
	var startSAMLJson string
	for scanner.Scan() {
		scanLine := strings.TrimSpace(scanner.Text())
		if strings.Contains(scanLine, "$Config") {
			startSAMLJson = scanLine[strings.Index(scanLine, "$Config=")+8 : strings.LastIndex(scanLine, ";")]
			break
		}
	}
	var startSAMLResp startSAMLResponse
	if err := json.Unmarshal([]byte(startSAMLJson), &startSAMLResp); err != nil {
		return samlAssertion, errors.Wrap(err, "startSAML response unmarshal error")
	}

	// password login
	loginValues := url.Values{}
	loginValues.Set(startSAMLResp.SFTName, startSAMLResp.SFT)
	loginValues.Set("ctx", startSAMLResp.SCtx)
	loginValues.Set("login", loginDetails.Username)
	loginValues.Set("passwd", loginDetails.Password)
	passwordLoginRequest, err := http.NewRequest("POST", startSAMLResp.URLPost, strings.NewReader(loginValues.Encode()))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving login results")
	}
	passwordLoginRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err = ac.client.Do(passwordLoginRequest)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving login results")
	}
	// data is embeded javascript object
	// <script><![CDATA[  $Config=......; ]]>
	scanner = bufio.NewScanner(res.Body)
	var loginPasswordJson string
	for scanner.Scan() {
		scanLine := strings.TrimSpace(scanner.Text())
		if strings.Contains(scanLine, "$Config") {
			loginPasswordJson = scanLine[strings.Index(scanLine, "$Config=")+8 : strings.LastIndex(scanLine, ";")]
			break
		}
	}
	var loginPasswordResp passwordLoginResponse
	var loginPasswordSkipMfaResp SkipMfaResponse
	if err := json.Unmarshal([]byte(loginPasswordJson), &loginPasswordResp); err != nil {
		return samlAssertion, errors.Wrap(err, "loginPassword response unmarshal error")
	}
	if err := json.Unmarshal([]byte(loginPasswordJson), &loginPasswordSkipMfaResp); err != nil {
		return samlAssertion, errors.Wrap(err, "loginPassword response unmarshal error")
	}

	// skip mfa
	if loginPasswordSkipMfaResp.URLSkipMfaRegistration != "" {
		res, err = ac.client.Get(loginPasswordSkipMfaResp.URLSkipMfaRegistration)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving skip mfa results")
		}
	} else {

		// start mfa
		mfas := loginPasswordResp.ArrUserProofs
		mfa := mfas[0]
		switch ac.idpAccount.MFA {

		case "Auto":
			for _, v := range mfas {
				if v.IsDefault {
					mfa = v
					break
				}
			}
		default:
			for _, v := range mfas {
				if v.AuthMethodID == ac.idpAccount.MFA {
					mfa = v
					break
				}
			}
		}
		mfaReq := mfaRequest{AuthMethodID: mfa.AuthMethodID, Method: "BeginAuth", Ctx: loginPasswordResp.SCtx, FlowToken: loginPasswordResp.SFT}
		mfaReqJson, err := json.Marshal(mfaReq)
		if err != nil {
			return samlAssertion, err
		}
		mfaBeginRequest, err := http.NewRequest("POST", loginPasswordResp.URLBeginAuth, strings.NewReader(string(mfaReqJson)))
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving begin mfa")
		}
		mfaBeginRequest.Header.Add("Content-Type", "application/json")
		res, err = ac.client.Do(mfaBeginRequest)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving begin mfa")
		}
		mfaBeginJson := make([]byte, res.ContentLength, res.ContentLength)
		if n, err := res.Body.Read(mfaBeginJson); err != nil && err != io.EOF || n != int(res.ContentLength) {
			return samlAssertion, errors.Wrap(err, "mfa BeginAuth response error")
		}
		var mfaResp mfaResponse
		if err := json.Unmarshal(mfaBeginJson, &mfaResp); err != nil {
			return samlAssertion, errors.Wrap(err, "mfa BeginAuth  response unmarshal error")
		}
		if !mfaResp.Success {
			return samlAssertion, fmt.Errorf("mfa BeginAuth is not success %v", mfaResp.Message)
		}

		//  mfa end
		for {
			mfaReq = mfaRequest{
				AuthMethodID: mfaResp.AuthMethodID,
				Method:       "EndAuth",
				Ctx:          mfaResp.Ctx,
				FlowToken:    mfaResp.FlowToken,
				SessionID:    mfaResp.SessionID,
			}
			if mfaReq.AuthMethodID == "PhoneAppOTP" {
				verifyCode := prompter.StringRequired("Enter verification code")
				mfaReq.AdditionalAuthData = verifyCode
			}
			mfaReqJson, err := json.Marshal(mfaReq)
			if err != nil {
				return samlAssertion, err
			}
			mfaEndRequest, err := http.NewRequest("POST", loginPasswordResp.URLEndAuth, strings.NewReader(string(mfaReqJson)))
			if err != nil {
				return samlAssertion, errors.Wrap(err, "error retrieving begin mfa")
			}
			mfaEndRequest.Header.Add("Content-Type", "application/json")
			res, err = ac.client.Do(mfaEndRequest)
			if err != nil {
				return samlAssertion, errors.Wrap(err, "error retrieving begin mfa")
			}
			mfaJson := make([]byte, res.ContentLength, res.ContentLength)
			if n, err := res.Body.Read(mfaJson); err != nil && err != io.EOF || n != int(res.ContentLength) {
				return samlAssertion, errors.Wrap(err, "mfa EndAuth response error")
			}
			if err := json.Unmarshal(mfaJson, &mfaResp); err != nil {
				return samlAssertion, errors.Wrap(err, "mfa EndAuth  response unmarshal error")
			}
			if mfaResp.ErrCode != 0 {
				return samlAssertion, fmt.Errorf("error mfa fail errcode: %d, message: %v", mfaResp.ErrCode, mfaResp.Message)
			}
			if mfaResp.Success {
				break
			}
			if !mfaResp.Retry {
				break
			}
			// if mfaResp.Retry == true then
			// must exist loginPasswordResp.OPerAuthPollingInterval[mfaResp.AuthMethodID]
			time.Sleep(time.Duration(loginPasswordResp.OPerAuthPollingInterval[mfaResp.AuthMethodID]) * time.Second)
		}
		if !mfaResp.Success {
			return samlAssertion, fmt.Errorf("error mfa fail")
		}

		// ProcessAuth
		ProcessAuthValues := url.Values{}
		ProcessAuthValues.Set(startSAMLResp.SFTName, mfaResp.FlowToken)
		ProcessAuthValues.Set("request", mfaResp.Ctx)
		ProcessAuthValues.Set("login", loginDetails.Username)

		ProcessAuthRequest, err := http.NewRequest("POST", loginPasswordResp.URLPost, strings.NewReader(ProcessAuthValues.Encode()))
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving process auth results")
		}
		ProcessAuthRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		res, err = ac.client.Do(ProcessAuthRequest)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving process auth results")
		}
		// data is embeded javascript object
		// <script><![CDATA[  $Config=......; ]]>
		scanner = bufio.NewScanner(res.Body)
		var ProcessAuthJson string
		for scanner.Scan() {
			scanLine := strings.TrimSpace(scanner.Text())
			if strings.Contains(scanLine, "$Config") {
				ProcessAuthJson = scanLine[strings.Index(scanLine, "$Config=")+8 : strings.LastIndex(scanLine, ";")]
				break
			}
		}
		var processAuthResp processAuthResponse
		if err := json.Unmarshal([]byte(ProcessAuthJson), &processAuthResp); err != nil {
			return samlAssertion, errors.Wrap(err, "ProcessAuth response unmarshal error")
		}

		// kmsi
		KmsiURL := res.Request.URL.Scheme + "://" + res.Request.URL.Host + processAuthResp.URLPost
		KmsiValues := url.Values{}
		KmsiValues.Set("flowToken", processAuthResp.SFT)
		KmsiValues.Set("ctx", processAuthResp.SCtx)

		KmsiRequest, err := http.NewRequest("POST", KmsiURL, strings.NewReader(KmsiValues.Encode()))
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving kmsi results")
		}
		KmsiRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		ac.client.DisableFollowRedirect()
		res, err = ac.client.Do(KmsiRequest)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error retrieving kmsi results")
		}
		ac.client.EnableFollowRedirect()
	}

	//  oidc
	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to build document from response")
	}
	// data in input tag
	authForm := url.Values{}
	var authSubmitURL string

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			return
		}
		value, ok := s.Attr("value")
		if !ok {
			return
		}
		authForm.Set(name, value)
	})

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		authSubmitURL = action
	})

	if authSubmitURL == "" {
		return samlAssertion, fmt.Errorf("unable to locate IDP oidc form submit URL")
	}

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	ac.client.EnableFollowRedirect()
	res, err = ac.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving oidc login form results")
	}

	//  get saml assertion
	oidcResponse, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "oidc login response error")
	}

	oidcResponseStr := string(oidcResponse)

	// data is embeded javascript
	// window.location = 'https:/..../?SAMLRequest=......'
	oidcResponseList := strings.Split(oidcResponseStr, ";")
	var SAMLRequestURL string
	for _, v := range oidcResponseList {
		if strings.Contains(v, "SAMLRequest") {
			startURLPos := strings.Index(v, "https://")
			endURLPos := strings.Index(v[startURLPos:], "'")
			if endURLPos == -1 {
				endURLPos = strings.Index(v[startURLPos:], "\"")
			}
			SAMLRequestURL = v[startURLPos : startURLPos+endURLPos]
		}

	}
	if SAMLRequestURL == "" {
		return samlAssertion, fmt.Errorf("unable to locate SAMLRequest URL")
	}

	req, err = http.NewRequest("GET", SAMLRequestURL, nil)

	res, err = ac.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retrieving oidc login form results")
	}

	// if mfa skipped then get $Config and urlSkipMfaRegistration
	// get urlSkipMfaRegistraition to return saml assertion
	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error oidc login response read")
	}
	resBodyStr := string(resBody)
	if strings.Contains(resBodyStr, "urlSkipMfaRegistration") {
		var samlAssertionSkipMfaResp SkipMfaResponse
		var skipMfaJson string
		responseList := strings.Split(resBodyStr, "<")
		for _, line := range responseList {

			if strings.Contains(line, "$Config") {
				skipMfaJson = line[strings.Index(line, "$Config=")+8 : strings.LastIndex(line, ";")]
				break
			}
		}
		if err := json.Unmarshal([]byte(skipMfaJson), &samlAssertionSkipMfaResp); err != nil {
			return samlAssertion, errors.Wrap(err, "SAMLAssertion skip mfa response unmarshal error")
		}
		res, err = ac.client.Get(samlAssertionSkipMfaResp.URLSkipMfaRegistration)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "SAMLAssertion skip mfa url get  error")
		}
		resBody, err = ioutil.ReadAll(res.Body)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "SAMLAssertion skip mfa request error")
		}
		resBodyStr = string(resBody)
	}

	// data in input tag
	doc, err = goquery.NewDocumentFromReader(strings.NewReader(resBodyStr))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		attrName, ok := s.Attr("name")
		if !ok {
			return
		}
		if attrName == "SAMLResponse" {
			samlAssertion, ok = s.Attr("value")
			if !ok {
				return
			}
		}
	})
	if samlAssertion == "" {
		return samlAssertion, fmt.Errorf("failed get SAMLAssersion")
	}
	return samlAssertion, nil
}
