package main

import (
	"flag"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/senghoo/modsecurity-go/libmodsecurity"
	"github.com/senghoo/modsecurity-go/modsecurity"
)

func main() {
	configs := flag.String("c", "modsecurity.conf,crs-setup.conf", "comma-separated list of conf files to load (in order) before the rules")
	rulePath := flag.String("r", "", "comma-separated list of paths to the sec rules folder(s)")
	rulePattern := flag.String("p", ".+\\.conf$", "pattern to apply before loading a file from the sec rules folder")
	flag.Parse()

	modSecurity := libmodsecurity.NewLibModSecurity()
	for _, conf := range strings.Split(*configs, ",") {
		err := modSecurity.AddRuleFromFile(conf)
		if err != nil {
			log.Printf("error loading the setup file (%s): %s", conf, err.Error())
			return
		}
	}

	if *rulePath != "" {
		loadRuleFolders(strings.Split(*rulePath, ","), *rulePattern, modSecurity)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})

	securedRouter := modsecurity.NewModMiddleWare(handler, modSecurity)

	s := &http.Server{
		Addr:           ":8080",
		Handler:        http.HandlerFunc(securedRouter.Handler),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())
}

func loadRuleFolders(folders []string, pattern string, modSecurity *libmodsecurity.LibModSecurity) {
	re := regexp.MustCompile(pattern)

	for _, folder := range folders {
		files, err := ioutil.ReadDir(folder)
		if err != nil {
			log.Printf("error scanning the rule folder: %s", err.Error())
			continue
		}

		for _, file := range files {
			filepath := path.Join(folder, file.Name())
			if !re.MatchString(filepath) {
				// log.Println("ignoring file", filepath)
				continue
			}

			log.Println("loading", filepath)
			err := modSecurity.AddRuleFromFile(filepath)
			if err != nil {
				log.Printf("error loading the rule file: %s", err.Error())
				return
			}
		}
	}
}
