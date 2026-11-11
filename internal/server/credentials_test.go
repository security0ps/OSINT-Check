package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirstRunAndStoredKeys(t *testing.T) {
	dir := t.TempDir()
	c, err := OpenCredentials(dir, "")
	if err != nil { t.Fatal(err) }
	s := build(t, Options{Credentials: c})
	code, err := os.ReadFile(filepath.Join(dir, "setup-code"))
	if err != nil { t.Fatal(err) }
	const password = "a long team password"
	payload, _ := json.Marshal(map[string]string{"code": strings.TrimSpace(string(code)), "password": password})
	const key = `{"name":"otx","value":"secret-test-key"}`
	if w := req(s, "PUT", "/api/key", local, key, nil); w.Code != 401 { t.Fatal(w.Code) }
	if w := req(s, "POST", "/api/login", local, `{"password":""}`, nil); w.Code != 401 { t.Fatal(w.Code) }
	if w := req(s, "POST", "/api/setup", local, `{"code":"wrong","password":"a long team password"}`, nil); w.Code != 403 { t.Fatal(w.Code) }
	for _, want := range []int{200, 403} {
		if w := req(s, "POST", "/api/setup", local, string(payload), nil); w.Code != want { t.Fatal(w.Code) }
	}
	w := req(s, "POST", "/api/login", local, `{"password":"a long team password"}`, nil)
	if w.Code != 200 { t.Fatal(w.Code) }
	auth := func(r *http.Request) { r.AddCookie(w.Result().Cookies()[0]) }
	if r := req(s, "PUT", "/api/key", local, key, auth); r.Code != 200 { t.Fatal(r.Code) }
	if r := req(s, "GET", "/api/meta", local, "", auth); strings.Contains(r.Body.String(), "secret-test-key") { t.Fatal("key disclosed") }
	c, err = OpenCredentials(dir, "")
	if err != nil { t.Fatal(err) }
	restarted := build(t, Options{Credentials: c})
	keys := map[string]string{}
	c.ApplyKeys(keys)
	if restarted.setupRequired() || !restarted.validPassword(password) || keys["otx"] != "secret-test-key" {
		t.Fatal("stored credentials did not survive restart")
	}
}
