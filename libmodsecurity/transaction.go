package libmodsecurity

// #cgo CFLAGS: -I/usr/local/modsecurity/include
// #cgo LDFLAGS: -L/usr/local/modsecurity/lib -lmodsecurity
// #include <modsecurity/modsecurity.h>
// #include <modsecurity/transaction.h>
// #include <modsecurity/rules.h>
import "C"

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
	var intervention C.Intervention
	intervention.status = 200
	intervention.url = nil
	if ret := C.msc_intervention(t.trans, &intervention); ret == 0 {
		return 0
	}

	if intervention.log == nil {
		intervention.log = "(no log message was specified)"
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
