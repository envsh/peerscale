package iptunnel

import (
	"io"
)

func writen(dst io.Writer, buf []byte, n int) (int, error) {
	wn := 0
	for wn < n {
		w, err := dst.Write(buf[wn:n])
		wn += w
		if err != nil {
			return wn, err
		}
	}
	return wn, nil
}
