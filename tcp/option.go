package tcp

import "reflect"

type Option struct {
	Kind byte
	Len  *byte
	Data []byte
}

type Options []Option

func (o *Option) Equal(o1 *Option) bool {
	if o.Kind != o1.Kind {
		return false
	}
	if o.Len == nil && o1.Len == nil {
		return true
	}
	if o.Len == nil || o1.Len == nil {
		return false
	}
	if *o.Len != *o1.Len {
		return false
	}
	return reflect.DeepEqual(o.Data, o1.Data)
}

func (o *Options) Equal(o1 *Options) bool {
	if len(*o) != len(*o1) {
		return false
	}
	for i := range *o {
		if !(*o)[i].Equal(&(*o1)[i]) {
			return false
		}
	}
	return true
}

// see https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
// ./tcp-parameters-1.csv
func ParseOptions(data []byte) Options {
	out := make([]Option, 0)
	cursor := 0
	total := len(data)
	for {
		if cursor >= total {
			break
		}
		kind := data[cursor]
		cursor++
		if kind == 0 || kind == 1 {
			out = append(out, Option{Kind: kind, Len: nil, Data: nil})
			continue
		}
		len := data[cursor]
		if (cursor + int(len) - 2) >= total {
			break
		}
		cursor++
		out = append(out, Option{Kind: kind, Len: &len, Data: data[cursor : cursor+int(len)-2]})
		cursor = cursor + int(len) - 2
	}

	return out
}

func (o *Option) Reply() *Option {
	ret := &Option{
		Kind: o.Kind,
		Len:  o.Len,
		Data: make([]byte, len(o.Data)),
	}

	if ret.Kind == 0x08 {
		copy(ret.Data[4:8], o.Data[0:4])
	}

	return ret
}

func (o *Options) Reply() *Options {
	ret := make(Options, len(*o))
	for i := range *o {
		ret[i] = *(*o)[i].Reply()
	}
	return &ret
}
