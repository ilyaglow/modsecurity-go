package libmodsecurity

//#include <modsecurity/modsecurity.h>
//#include <modsecurity/transaction.h>
//#include <modsecurity/rules.h>

import "C"
import "fmt"

type LibModSecurity struct {
	modsec *C.ModSecurity
	rules  *C.Rules
}

func NewLibModSecurity() {
	return &LibModSecurity{
		rules: msc_init(),
		rules: msc_create_rules_set(),
	}
}

func (l *LibModSecurity) AddRuleFromRemote(key, url string) error {
	var errStrPoint *C.char
	res := C.msc_rules_add_remote(l.rules, key, url, &errStrPoint)
	if res < 0 {
		errString := C.GoString(errStrPoint)
		return fmt.Errorf("Failed to load the rules from %s - reason %s", url, errString)
	}
	return nil
}

func (l *LibModSecurity) AddRuleFromFile(rulefile string) error {
	var errStrPoint *C.char
	res := C.msc_rules_add_file(l.rules, rulefile, &errStrPoint)
	if res < 0 {
		errString := C.GoString(errStrPoint)
		return fmt.Errorf("Failed to load the rules from %s - reason %s", rulefile, errString)
	}
	return nil
}

func (l *LibModSecurity) AddRule(rules string) error {
	var errStrPoint *C.char
	res := C.msc_rules_add(l.rules, rules, &errStrPoint)
	if res < 0 {
		errString := C.GoString(errStrPoint)
		return fmt.Errorf("Failed to load the rule %s - reason %s", rules, errString)
	}
	return nil
}
