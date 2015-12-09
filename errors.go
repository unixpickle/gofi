package gofi

import "errors"

var (
	ErrBufferUnderflow = errors.New("buffer underflow")
	ErrClosed          = errors.New("cannot operate on closed handle")
)
