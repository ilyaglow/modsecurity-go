package libmodsecurity

import (
	"os"
	"testing"
)

var libmodsecurity *LibModSecurity

func TestVar(t *testing.T) {
	libmodsecurity.AddRule("SecRuleEngine On")
	err := libmodsecurity.AddRule("SecRule REQUEST_LINE \"@contains php\" \"id:1,phase:1,deny\"")
	if err != nil {
		t.Fatal("cant add rule ", err)
	}
	trans := libmodsecurity.NewTransaction()
	trans.ProcessConnection("192.168.1.1", "192.168.1.2", 22345, 80)
	trans.ProcessURL("/a.php?test=test", "GET ", 1, 1)
	trans.ProcessRequestHeader()
	i := trans.Intervention()
	if i == nil {
		t.Fatal("intervention return nil fail")
	}
}

func TestMain(m *testing.M) {
	setup()
	ret := m.Run()
	if ret == 0 {
		teardown()
	}
	os.Exit(ret)
}

func setup() {
	libmodsecurity = NewLibModSecurity()

}

func teardown() {
}
