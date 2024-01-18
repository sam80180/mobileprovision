package mobileprovision

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	cms "github.com/github/ietf-cms"
	mime "github.com/qingstor/go-mime"
	"golang.org/x/crypto/ocsp"
	"howett.net/plist"
)

type Entitlements struct {
	ApplicationIdentifier string   `plist:"application-identifier,omitempty" json:"application-identifier,omitempty" mapstructure:"application-identifier,omitempty"`
	GetTaskAllow          bool     `plist:"get-task-allow,omitempty" json:"get-task-allow,omitempty" mapstructure:"get-task-allow,omitempty"`
	KeyChainAccessGroups  []string `plist:"keychain-access-groups,omitempty" json:"keychain-access-groups,omitempty" mapstructure:"keychain-access-groups,omitempty"`
	TeamIdentifier        string   `plist:"com.apple.developer.team-identifier,omitempty" json:"com.apple.developer.team-identifier,omitempty" mapstructure:"com.apple.developer.team-identifier,omitempty"`
}

type ProvisioningProfile struct { // https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles
	_raw []byte `json:"-"`

	AppIDName                   string       `plist:"AppIDName,omitempty"`
	ApplicationIdentifierPrefix []string     `plist:"ApplicationIdentifierPrefix,omitempty"`
	CreationDate                time.Time    `plist:"CreationDate,omitempty"`
	Platform                    []string     `plist:"Platform,omitempty"`
	IsXcodeManaged              bool         `plist:"IsXcodeManaged,omitempty"`
	DeveloperCertificates       [][]byte     `plist:"DeveloperCertificates,omitempty"` // array of base64-encoded DER certificates
	DEREncodedProfile           []byte       `plist:"DER-Encoded-Profile,omitempty" json:"-"`
	PPQCheck                    bool         `plist:"PPQCheck,omitempty"`
	Entitlements                Entitlements `plist:"Entitlements,omitempty"`
	ExpirationDate              time.Time    `plist:"ExpirationDate,omitempty"`
	Name                        string       `plist:"Name,omitempty"` // profile name
	ProvisionsAllDevices        bool         `plist:"ProvisionsAllDevices,omitempty" json:"ProvisionsAllDevices,omitempty"`
	ProvisionedDevices          []string     `plist:"ProvisionedDevices,omitempty"`
	TeamIdentifier              []string     `plist:"TeamIdentifier,omitempty"`
	TeamName                    string       `plist:"TeamName,omitempty"`
	TimeToLive                  int          `plist:"TimeToLive,omitempty"`
	UUID                        string       `plist:"UUID,omitempty"`
	Version                     int          `plist:"Version,omitempty"`
}

type ProvisioningProfileDtoJson struct {
	ProvisioningProfile

	// for JSON output
	DeveloperCertificates []string
	DEREncodedProfile     string `json:"DER-Encoded-Profile,omitempty"`
}

func cms_parse(raw []byte) ([]byte, error) {
	d, err := cms.ParseSignedData(raw)
	if err != nil {
		return nil, err
	}
	return d.GetData()
}

func Load(raw []byte) (*ProvisioningProfile, error) {
	c, err := cms_parse(raw)
	if err != nil {
		return nil, err
	}
	var pp ProvisioningProfile
	dec := plist.NewDecoder(bytes.NewReader(c))
	if err := dec.Decode(&pp); err != nil {
		return nil, err
	}
	pp._raw = raw
	return &pp, nil
}

func (oneself *ProvisioningProfile) IsUDIDProvisioned(udid string) bool {
	if oneself.ProvisionsAllDevices {
		return true
	}
	for _, deviceSN := range oneself.ProvisionedDevices {
		if udid == deviceSN || udid == strings.Replace(deviceSN, "-", "", -1) {
			return true
		}
	}
	return false
}

func (oneself *ProvisioningProfile) GetDeveloperCertificates() (cert []*x509.Certificate, err []error) {
	for _, raw := range oneself.DeveloperCertificates {
		c, e := x509.ParseCertificate(raw)
		err = append(err, e)
		cert = append(cert, c)
	}
	return
}

func (oneself *ProvisioningProfile) IsProfileExpired() bool {
	return time.Now().After(oneself.ExpirationDate)
}

func doOCSP(certClient, certIssuer *x509.Certificate, ocspServerUrl string) (int, error) { // https://www.cossacklabs.com/blog/tls-validation-implementing-ocsp-and-crl-in-go/
	if len(certClient.OCSPServer) <= 0 {
		return ocsp.Unknown, nil
	}
	url, err := url.Parse(ocspServerUrl)
	if err != nil {
		return ocsp.Unknown, err
	}
	buffer, err := ocsp.CreateRequest(certClient, certIssuer, &ocsp.RequestOptions{Hash: crypto.SHA256})
	if err != nil {
		return ocsp.Unknown, err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, ocspServerUrl, bytes.NewBuffer(buffer))
	if err != nil {
		return ocsp.Unknown, err
	}
	httpRequest.Header.Add("Content-Type", mime.DetectFileExt("ORQ"))
	httpRequest.Header.Add("Accept", mime.DetectFileExt("ORS"))
	httpRequest.Header.Add("Host", url.Host)
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return ocsp.ServerFailed, err
	}
	defer httpResponse.Body.Close()
	output, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		return ocsp.Unknown, err
	}
	ocspResponse, err := ocsp.ParseResponseForCert(output, certClient, certIssuer)
	if err != nil {
		return ocsp.Unknown, err
	}
	return ocspResponse.Status, nil
}

func getOCSPStatus(certClient *x509.Certificate) (int, error) {
	if len(certClient.IssuingCertificateURL) <= 0 {
		return ocsp.Unknown, nil
	}
	var err error = nil
	for _, issuerUrl := range certClient.IssuingCertificateURL {
		response, err := http.Get(issuerUrl)
		if err != nil {
			continue
		}
		defer response.Body.Close()
		bodyBytes, err := io.ReadAll(response.Body)
		if err != nil {
			continue
		}
		certIssuer, err := x509.ParseCertificate(bodyBytes)
		if err != nil {
			continue
		}
		for _, ocspServerUrl := range certClient.OCSPServer {
			var ocspStatus int
			ocspStatus, err = doOCSP(certClient, certIssuer, ocspServerUrl)
			if err != nil {
				continue
			}
			if ocspStatus != ocsp.ServerFailed {
				return ocspStatus, nil
			}
		}
	}
	return ocsp.Unknown, err
}

func (oneself *ProvisioningProfile) DeveloperCertificateOCSPStatus() (status []int, err []error) {
	cc, ee := oneself.GetDeveloperCertificates()
	for i, c := range cc {
		if ee[i] != nil {
			status = append(status, ocsp.Unknown)
			err = append(err, ee[i])
			continue
		}
		s, e := getOCSPStatus(c)
		status = append(status, s)
		err = append(err, e)
	}
	return
}

func (oneself *ProvisioningProfile) ToBytes() []byte {
	return oneself._raw
}

func (oneself *ProvisioningProfile) ToPlist() ([]byte, error) {
	return cms_parse(oneself._raw)
}

func (oneself *ProvisioningProfile) ToJSON() ([]byte, error) {
	dto := ProvisioningProfileDtoJson{ProvisioningProfile: *oneself}
	certs := []string{}
	for _, cert := range oneself.DeveloperCertificates {
		certs = append(certs, base64.StdEncoding.EncodeToString(cert))
	}
	dto.DeveloperCertificates = certs
	dto.DEREncodedProfile = base64.StdEncoding.EncodeToString(oneself.DEREncodedProfile)
	return json.Marshal(dto)
}
