package httpntlm

import (
	"crypto/tls"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vadimi/go-ntlm/ntlm"
)

// NtlmTransport is implementation of http.RoundTripper interface
type NtlmTransport struct {
	TLSClientConfig *tls.Config
	Domain          string
	User            string
	Password        string
}

// RoundTrip method send http request and tries to perform NTLM authentication
func (t NtlmTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	// first send NTLM Negotiate header
	r, _ := http.NewRequest("GET", req.URL.String(), strings.NewReader(""))
	r.Header.Add("Authorization", "NTLM "+encBase64(negotiate()))

	client := http.Client{Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       t.TLSClientConfig,
	}}

	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}

	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		// it's necessary to reuse the same http connection
		// in order to do that it's required to read Body and close it
		_, err = io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			return nil, err
		}
		err = resp.Body.Close()
		if err != nil {
			return nil, err
		}

		// retrieve Www-Authenticate header from response
		ntlmChallengeHeader := resp.Header.Get("WWW-Authenticate")
		if ntlmChallengeHeader == "" {
			return nil, errors.New("Wrong WWW-Authenticate header")
		}

		ntlmChallengeString := strings.Replace(ntlmChallengeHeader, "NTLM ", "", -1)
		challengeBytes, err := decBase64(ntlmChallengeString)
		if err != nil {
			return nil, err
		}

		session, err := ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionlessMode)
		if err != nil {
			return nil, err
		}

		session.SetUserInfo(t.User, t.Password, t.Domain)

		// parse NTLM challenge
		challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
		if err != nil {
			return nil, err
		}

		err = session.ProcessChallengeMessage(challenge)
		if err != nil {
			return nil, err
		}

		// authenticate user
		authenticate, err := session.GenerateAuthenticateMessage()
		if err != nil {
			return nil, err
		}

		// set NTLM Authorization header
		req.Header.Set("Authorization", "NTLM "+encBase64(authenticate.Bytes()))
		return client.Do(req)
	}

	return resp, err
}
