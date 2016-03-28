package httpntlm

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
)

func Test_AuthenticationSuccess(t *testing.T) {
	client := http.Client{
		Transport: &NtlmTransport{
			Domain:   "dt",
			User:     "testuser",
			Password: "fish",
		},
	}

	session, _ := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionlessMode)
	session.SetUserInfo("testuser", "fish", "dt")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		h := r.Header.Get("Authorization")
		if h == "" {
			w.WriteHeader(401)
			return
		}

		ntlmChallengeString := strings.Replace(h, "NTLM ", "", -1)
		authenticateBytes, _ := decBase64(ntlmChallengeString)
		auth, err := ntlm.ParseAuthenticateMessage(authenticateBytes, 2)
		if err == nil {
			err = session.ProcessAuthenticateMessage(auth)
			if err != nil {
				t.Errorf("Could not process authenticate message: %s\n", err)
				return
			}
		} else {
			challenge, _ := session.GenerateChallengeMessage()
			w.Header().Add("WWW-Authenticate", "NTLM "+encBase64(challenge.Bytes()))
			w.WriteHeader(401)
		}
	}))

	defer ts.Close()
	req, err := http.NewRequest("GET", ts.URL, strings.NewReader(""))
	resp, err := client.Do(req)

	if err != nil {
		t.Error(err)
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			t.Error(err)
		}
	}()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}

}
