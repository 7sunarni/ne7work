package tcp

/*
fin : 1,
syn : 1,
rst : 1,
psh : 1,
ack : 1,
urg : 1,
ece : 1,
cwr : 1;
*/

type Flags struct {
	Fin bool
	Syn bool
	Rst bool
	Psh bool
	Ack bool
	Urg bool
	Ece bool
	Cwr bool
}

func parseFlags(data byte) Flags {
	return Flags{
		Fin: data&0x01 != 0,
		Syn: data&0x02 != 0,
		Rst: data&0x04 != 0,
		Psh: data&0x08 != 0,
		Ack: data&0x10 != 0,
		Urg: data&0x20 != 0,
		Ece: data&0x40 != 0,
		Cwr: data&0x80 != 0,
	}
}

func (f *Flags) ToByte() byte {
	var b byte
	if f.Fin {
		b |= 1 << 0
	}
	if f.Syn {
		b |= 1 << 1
	}
	if f.Rst {
		b |= 1 << 2
	}
	if f.Psh {
		b |= 1 << 3
	}
	if f.Ack {
		b |= 1 << 4
	}
	if f.Urg {
		b |= 1 << 5
	}
	if f.Ece {
		b |= 1 << 6
	}
	if f.Cwr {
		b |= 1 << 7
	}
	return b
}
