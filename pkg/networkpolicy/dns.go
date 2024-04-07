package networkpolicy

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

func processDNSPacket(b []byte, wantName string, isTCP bool) {
	if isTCP {
		// As per RFC 1035, TCP DNS messages are preceded by a 16 bit size, skip first 2 bytes.
		b = b[2:]
	} else {
		// RFC1035 max 512 bytes for UDP
		if len(b) > 512 {
			return
		}

	}

	var p dnsmessage.Parser
	_, err := p.Start(b)
	if err != nil {
		return
	}

	for {
		q, err := p.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			panic(err)
		}

		if q.Name.String() != wantName {
			continue
		}

		fmt.Println("Found question for name", wantName)
		if err := p.SkipAllQuestions(); err != nil {
			panic(err)
		}
		break
	}

	var gotIPs []net.IP
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			panic(err)
		}

		if (h.Type != dnsmessage.TypeA && h.Type != dnsmessage.TypeAAAA) || h.Class != dnsmessage.ClassINET {
			continue
		}

		if !strings.EqualFold(h.Name.String(), wantName) {
			if err := p.SkipAnswer(); err != nil {
				panic(err)
			}
			continue
		}

		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				panic(err)
			}
			gotIPs = append(gotIPs, r.A[:])
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				panic(err)
			}
			gotIPs = append(gotIPs, r.AAAA[:])
		}
	}

}
