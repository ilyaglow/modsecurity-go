package modsecurity

import (
	"net/http"

	"github.com/senghoo/modsecurity-go/libmodsecurity"
)

type MiddleWare struct {
	modsecurity *libmodsecurity.LibModSecurity
	handler     http.Handler
}

func NewModMiddleWare(h http.Handler, lib *libmodsecurity.LibModSecurity) *MiddleWare {
	return &MiddleWare{
		modsecurity: lib,
		handler:     h,
	}
}

func (m *MiddleWare) Handler(w http.ResponseWriter, r *http.Request) {
	c := m.newConnection(w, r)
	if !c.checkRequestHeader() {
		writer := c.getResponseWriter()
		r.Body = c.getRequestBodyReader()
		m.handler.ServeHTTP(writer, r)
	}
	if c.intervention != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}
}
