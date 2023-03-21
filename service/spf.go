package service

import (
	"errors"
	conf "github.com/muety/mailwhale/config"
	"github.com/emvi/logbuch"
	"net"
	"strings"
)

type SpfService struct {
	config *conf.Config
}

func NewSpfService() *SpfService {
	return &SpfService{
		config: conf.Get(),
	}
}

func (s *SpfService) Validate(domain string) error {
	spfRecords, err := findSpfRecords(domain)
	if err != nil {
		return err
	}

	for _, rr := range spfRecords {
		logbuch.Debug("looking for our mail domain '%v' in spf record for user domain '%v': '%v'", s.config.Mail.Domain, domain, rr)
		if strings.Contains(rr, "include:"+s.config.Mail.Domain) {
			return nil
		}
	}

	return errors.New("spf check did not pass")
}

func findSpfRecords(domain string) ([]string, error) {
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return nil, err
	}
	spfs := make([]string, 0, len(txts))
	for _, rr := range txts {
		if strings.HasPrefix(rr, "v=spf1") {
			spfs = append(spfs, rr)
		}
	}
	return spfs, nil
}
