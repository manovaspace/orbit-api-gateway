package httpapi

import (
	"net/http"
	"net/http/httptest"
)

func httptestReq(method, path, bearer string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	return r
}

func httptestRec() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}
