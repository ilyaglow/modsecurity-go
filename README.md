# This Source not working yet now !!!

# ModSecurity-Go
ModSecurity middleware for go

# Dependency

* [LibModSecurity](https://github.com/SpiderLabs/ModSecurity/tree/libmodsecurity) 

# Install 

[Install Guide](https://github.com/senghoo/modsecurity-go/blob/master/doc/install.md)

# Usage 

## LibModSecurity

```
libmodsecurity := NewLibModSecurity()
libmodsecurity.addRule("...")

trans := libmodsecurity.NewTransaction()
trans.ProcessConnection("192.168.1.2","www.example.com", 55332, 80)
trans.ProcessURL("/a.php?test=test", "GET ", 1, 1)
trans.ProcessRequestHeader()
checkThis :=  trans.Intervention() 

```
