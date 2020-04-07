package main

import (
	"io/ioutil"
	"log"
)

func main() {
	d, err := newMfsVolumeDriver()
	if err != nil {
		panic(err)
	}

	// stop the go-plugins-helpers code from logging
	log.SetOutput(ioutil.Discard)

	h := d.newHandler()
	socketGroupId := 0
	panic(h.ServeUnix(d.SocketFile, socketGroupId))
}
