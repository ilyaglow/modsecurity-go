package modsecurity

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/senghoo/modsecurity-go/libmodsecurity"
)

type connection struct {
	trans          *libmodsecurity.Transaction
	responseWriter http.ResponseWriter
	request        *http.Request
	intervention   *libmodsecurity.Intervention
}

func (m *MiddleWare) newConnection(w http.ResponseWriter, r *http.Request) *connection {
	return &connection{
		trans:          m.modsecurity.NewTransaction(),
		responseWriter: w,
		request:        r,
	}
}

func (m *connection) getIntervention() *libmodsecurity.Intervention {
	return m.intervention
}

func (m *connection) setIntervention(intervention *libmodsecurity.Intervention) {
	m.intervention = intervention
}

func (m *connection) checkRequestHeader() (ok bool) {
	//process connection
	pair := strings.Split(m.request.RemoteAddr, ":")
	ip := pair[0]
	port, _ := strconv.Atoi(pair[1])
	// FIXME: set server to real addr and port
	m.trans.ProcessConnection(ip, "0.0.0.0", port, 80)
	m.intervention = m.trans.Intervention()
	if m.intervention != nil {
		return true
	}

	//process url
	m.trans.ProcessURL(m.getURL().String(), m.request.Method, m.request.ProtoMajor, m.request.ProtoMinor)
	m.intervention = m.trans.Intervention()
	if m.intervention != nil {
		return true
	}

	// process header
	for key, values := range m.request.Header {
		for _, value := range values {
			m.trans.AddRequestHeader(key, value)
			m.intervention = m.trans.Intervention()
			if m.intervention != nil {
				return true
			}
		}
	}

	m.trans.ProcessRequestHeader()
	m.intervention = m.trans.Intervention()
	if m.intervention != nil {
		return true
	}
	return false
}

func (m *connection) getURL() *url.URL {
	url := *m.request.URL
	// FIXME: get url scheme
	url.Scheme = "http"
	url.Host = m.request.Host
	return &url
}

func (m *connection) checkResponseHeader() (ok bool) {
	for key, values := range m.responseWriter.Header() {
		for _, value := range values {
			m.trans.AddResponseHeader(key, value)
			m.intervention = m.trans.Intervention()
			if m.intervention != nil {
				return true
			}
		}
	}

	m.trans.ProcessResponseHeader()
	m.intervention = m.trans.Intervention()
	if m.intervention != nil {
		return true
	}
	return false
}
