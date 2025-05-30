package tcp

type Payload struct {
	Options Options
	Data    []byte
}

func (p *Payload) ToBytes() []byte {
	ret := make([]byte, 0)
	ret = append(ret, p.Options.Bytes()...)
	ret = append(ret, p.Data...)
	return ret
}

type PayloadParser struct {
	cursor  int
	options Options
	raw     []byte
}

func NewPayloadParser(data []byte) *PayloadParser {
	return &PayloadParser{
		cursor:  0,
		options: make([]Option, 0),
		raw:     data,
	}
}

func (p *PayloadParser) parse() Payload {
	p.ParseOptions()
	return Payload{
		Options: p.options,
		Data:    p.raw[p.cursor:],
	}
}
