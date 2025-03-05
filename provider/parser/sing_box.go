package parser

import (
	"context"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/service"
)

type _Outbound struct {
	Type    string `json:"type"`
	Tag     string `json:"tag,omitempty"`
	Options any    `json:"-"`
}

type Outbound _Outbound

type SingBoxDocument struct {
	Outbounds []Outbound `json:"outbounds"`
}

func (h *Outbound) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	err := json.UnmarshalContext(ctx, content, (*_Outbound)(h))
	if err != nil {
		return err
	}
	switch h.Type {
	case C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeSelector, C.TypeURLTest:
		return nil
	}
	registry := service.FromContext[option.OutboundOptionsRegistry](ctx)
	if registry == nil {
		return E.New("missing outbound options registry in context")
	}
	options, loaded := registry.CreateOptions(h.Type)
	if !loaded {
		return E.New("unknown outbound type: ", h.Type)
	}
	err = badjson.UnmarshallExcludedContext(ctx, content, (*_Outbound)(h), options)
	if err != nil {
		return err
	}
	if listenWrapper, isListen := options.(option.ListenOptionsWrapper); isListen {
		//nolint:staticcheck
		if listenWrapper.TakeListenOptions().InboundOptions != (option.InboundOptions{}) {
			deprecated.Report(ctx, deprecated.OptionInboundOptions)
		}
	}
	h.Options = options
	return nil
}

func ParseBoxSubscription(ctx context.Context, content string) ([]option.Outbound, error) {
	options, err := json.UnmarshalExtendedContext[SingBoxDocument](ctx, []byte(content))
	if err != nil {
		return nil, err
	}
	outs := common.Filter(options.Outbounds, func(it Outbound) bool {
		switch it.Type {
		case C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeSelector, C.TypeURLTest:
			return false
		default:
			return true
		}
	})
	if len(outs) == 0 {
		return nil, E.New("no servers found")
	}
	outbounds := common.Map(outs, func(it Outbound) option.Outbound {
		return (option.Outbound)(it)
	})
	return outbounds, nil
}
