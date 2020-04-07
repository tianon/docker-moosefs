package main

import (
	"io/ioutil"
	"log"
	"strings"

	"github.com/spf13/pflag"
)

func main() {
	flagOpts := pflag.StringSliceP("opt", "o", nil, "default opts for mfsmount")
	pflag.Parse()

	defaultOpts := map[string]string{}
	for _, opt := range *flagOpts {
		if i := strings.IndexRune(opt, '='); i >= 0 {
			val := opt[i+1:]
			opt = opt[:i]
			defaultOpts[opt] = val
		} else {
			defaultOpts[opt] = ""
		}
	}

	d, err := newMfsVolumeDriver(defaultOpts)
	if err != nil {
		panic(err)
	}

	// stop the go-plugins-helpers code from logging
	log.SetOutput(ioutil.Discard)

	h := d.newHandler()
	socketGroupId := 0
	panic(h.ServeUnix(d.SocketFile, socketGroupId))
}
