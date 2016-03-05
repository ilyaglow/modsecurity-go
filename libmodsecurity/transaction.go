package libmodsecurity

// #cgo CFLAGS: -I/usr/local/modsecurity/include
// #cgo LDFLAGS: -L/usr/local/modsecurity/lib -lmodsecurity
// #include <modsecurity/modsecurity.h>
// #include <modsecurity/transaction.h>
// #include <modsecurity/rules.h>
// #include <string.h>
// char * no_log_msg = "(no log message was specified)";
import "C"
import (
	"fmt"
	"unsafe"
)

type Transaction struct {
	trans *C.Transaction
}

type Intervention struct {
	status int
	url    string
	log    string
}

func (l *LibModSecurity) NewTransaction() *Transaction {
	return &Transaction{
		trans: C.msc_new_transaction(l.modsec, l.rules, nil),
	}
}

func (t *Transaction) Intervention() *Intervention {
	var intervention C.ModSecurityIntervention
	intervention.status = 200
	intervention.url = nil
	if ret := C.msc_intervention(t.trans, &intervention); ret == 0 {
		return nil
	}

	if intervention.log == nil {
		intervention.log = C.no_log_msg
	}

	return &Intervention{
		status: int(intervention.status),
		url:    C.GoString(intervention.url),
		log:    C.GoString(intervention.log),
	}
}

func (t *Transaction) ProcessConnection(clientAddr, serverAddr string, clientPort, serverPort int) {
	cClientPort := C.int(clientPort)
	cServerPort := C.int(serverPort)
	cClientAddr := C.CString(clientAddr)
	cServerAddr := C.CString(serverAddr)
	defer C.free(cClientAddr)
	defer C.free(cServerAddr)
	C.msc_process_connection(t.trans, cClientAddr, cClientPort, cServerAddr, cServerPort)
}

func (t *Transaction) ProcessURL(url, method string, major, minor int) {
	cVersion := C.CString(fmt.Sprintf("%d.%d", major, minor))
	cURL := C.CString(url)
	cMethod := C.CString(method)
	defer C.free(cVersion)
	defer C.free(cURL)
	defer C.free(cMethod)
	C.msc_process_uri(t.trans, cURL, cMethod, cVersion)
}

func (t *Transaction) AddRequestHeader(key, value string) {
	cKey := C.CString(key)
	cVal := C.CString(value)
	cUKey := (*C.uchar)(unsafe.Pointer(cKey))
	cUVal := (*C.uchar)(unsafe.Pointer(cVal))
	defer C.free(cKey)
	defer C.free(cVal)

	C.msc_add_n_request_header(t.trans, cUKey, C.strlen(cKey), cUVal, C.strlen(cVal))
}

func (t *Transaction) ProcessRequestHeader() {
	C.msc_process_request_headers(t.trans)
}

func (t *Transaction) RequestBodyFromFile(filename string) {
	cFilename := C.CString(filename)
	defer C.free(cFilename)
	C.msc_request_body_from_file(t.trans, cFilename)
}

func (t *Transaction) AppendRequestBody(body []byte) {
	uBody := (*C.uchar)(unsafe.Pointer(&body[0]))
	C.msc_append_request_body(t.trans, uBody, C.size_t(len(body)))
}

func (t *Transaction) ProcessRequestBody() {
	C.msc_process_request_body(t.trans)
}

func (t *Transaction) AddResponseHeader(key, value string) {
	cKey := C.CString(key)
	cVal := C.CString(value)
	cUKey := (*C.uchar)(unsafe.Pointer(cKey))
	cUVal := (*C.uchar)(unsafe.Pointer(cVal))
	defer C.free(cKey)
	defer C.free(cVal)

	C.msc_add_n_response_header(t.trans, cUKey, C.strlen(cKey), cUVal, C.strlen(cVal))
}

func (t *Transaction) ProcessResponseHeader() {
	C.msc_process_response_headers(t.trans)
}

func (t *Transaction) AppendResponseBody(body []byte) {
	uBody := (*C.uchar)(unsafe.Pointer(&body[0]))
	C.msc_append_response_body(t.trans, uBody, C.size_t(len(body)))
}

func (t *Transaction) ProcessResponseBody() {
	C.msc_process_response_body(t.trans)
}
