package libmodsecurity

// #cgo CFLAGS: -I/usr/local/modsecurity/include
// #cgo LDFLAGS: -L/usr/local/modsecurity/lib -lmodsecurity
// #include <modsecurity/modsecurity.h>
// #include <modsecurity/transaction.h>
// #include <modsecurity/rules.h>
import "C"

import (
	"fmt"
	"unsafe"
)

type LibModSecurity struct {
	modsec *C.ModSecurity
	rules  *C.Rules
}

func NewLibModSecurity() *LibModSecurity {
	return &LibModSecurity{
		modsec: C.msc_init(),
		rules:  C.msc_create_rules_set(),
	}
}

func (l *LibModSecurity) AddRuleFromRemote(key, url string) error {
	var errStrPoint *C.char
	cKey := C.CString(key)
	cUrl := C.CString(url)
	defer C.free(unsafe.Pointer(cKey))
	defer C.free(unsafe.Pointer(cUrl))
	res := C.msc_rules_add_remote(l.rules, cKey, cUrl, &errStrPoint)
	if res < 0 {
		errString := C.GoString(errStrPoint)
		return fmt.Errorf("Failed to load the rules from %s - reason %s", url, errString)
	}
	C.msc_rules_dump(l.rules)
	return nil
}

func (l *LibModSecurity) AddRuleFromFile(rulefile string) error {
	var errStrPoint *C.char
	cRulefile := C.CString(rulefile)
	defer C.free(unsafe.Pointer(cRulefile))
	res := C.msc_rules_add_file(l.rules, cRulefile, &errStrPoint)
	if res < 0 {
		errString := C.GoString(errStrPoint)
		return fmt.Errorf("Failed to load the rules from %s - reason %s", rulefile, errString)
	}
	C.msc_rules_dump(l.rules)
	return nil
}

func (l *LibModSecurity) AddRule(rules string) error {
	var errStrPoint *C.char
	cRules := C.CString(rules)
	defer C.free(unsafe.Pointer(cRules))
	res := C.msc_rules_add(l.rules, cRules, &errStrPoint)
	if res < 0 {
		errString := C.GoString(errStrPoint)
		return fmt.Errorf("Failed to load the rule %s - reason %s", rules, errString)
	}
	C.msc_rules_dump(l.rules)
	return nil
}
