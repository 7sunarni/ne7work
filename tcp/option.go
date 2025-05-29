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

func (o *Option) Reply() *Option {
	ret := &Option{
		Kind: o.Kind,
		Len:  o.Len,
		Data: o.Data,
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

func (o *Option) Bytes() []byte {
	ret := make([]byte, 0)
	ret = append(ret, o.Kind)
	if o.Len != nil {
		ret = append(ret, *o.Len)
	}
	if o.Data != nil {
		ret = append(ret, o.Data...)
	}
	return ret
}

func (o *Options) Bytes() []byte {
	ret := make([]byte, 0)
	for _, v := range *o {
		ret = append(ret, v.Bytes()...)
	}
	return ret
}

// todo
// see https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
// ./tcp-parameters-1.csv
func (p *PayloadParser) ParseOptions() {
	total := len(p.raw)
	for {
		if p.cursor >= total-1 {
			break
		}
		kind := p.raw[p.cursor]
		p.cursor++
		if kind == 0 {
			p.options = append(p.options, Option{Kind: kind, Len: nil, Data: nil})
			break
		}
		if kind == 1 {
			p.options = append(p.options, Option{Kind: kind, Len: nil, Data: nil})
			continue
		}
		if kind == 11 {
			p.options = append(p.options, Option{Kind: kind, Len: nil, Data: nil})
			continue
		}
		if kind == 12 {
			p.options = append(p.options, Option{Kind: kind, Len: nil, Data: nil})
			continue
		}
		if kind == 13 {
			p.options = append(p.options, Option{Kind: kind, Len: nil, Data: nil})
			continue
		}

		if kind >= 35 && kind <= 56 {
			p.cursor--
			break
		}
		len := p.raw[p.cursor]
		if (p.cursor - 1 + int(len)) > total {
			p.cursor--
			break
		}
		if kind == 3 {
			if len != 3 {
				p.cursor--
				break
			}
		}
		if kind == 19 {
			if len != 18 {
				p.cursor--
				break
			}
		}
		p.cursor++
		p.options = append(p.options, Option{Kind: kind, Len: &len, Data: p.raw[p.cursor : p.cursor+int(len)-2]})
		p.cursor = p.cursor + int(len) - 2
	}
}
