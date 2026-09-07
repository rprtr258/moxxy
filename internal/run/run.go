package run

import (
	"context"
	"errors"
	"slices"
	"strings"
)

type Lifecycle struct {
	closers []func(context.Context) error
}

func New() *Lifecycle {
	return &Lifecycle{}
}

func (lc *Lifecycle) AddCE(closer func(context.Context) error) {
	lc.closers = append(lc.closers, closer)
}

func (lc *Lifecycle) AddE(closer func() error) {
	lc.AddCE(func(context.Context) error {
		return closer()
	})
}

func (lc *Lifecycle) Add(closer func()) {
	lc.AddCE(func(context.Context) error {
		closer()
		return nil
	})
}

func (lc *Lifecycle) Close(ctx context.Context) error {
	var e strings.Builder
	for _, v := range slices.Backward(lc.closers) {
		if err := v(ctx); err != nil {
			e.WriteString(err.Error())
		}
	}
	if e.String() != "" {
		return errors.New(e.String())
	}
	return nil
}
