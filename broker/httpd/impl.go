package httpd

import (
	"time"

	dnslbcfg "github.com/Cloud-Foundations/golib/pkg/loadbalancing/dnslb/config"
	"github.com/Cloud-Foundations/golib/pkg/watchdog"
)

func (s *Server) performStateCleanup(secsBetweenCleanup int) {
	for {
		s.cookieMutex.Lock()
		for key, authCookie := range s.authCookie {
			if authCookie.ExpiresAt.Before(time.Now()) {
				delete(s.authCookie, key)
			}
		}
		s.cookieMutex.Unlock()
		time.Sleep(time.Duration(secsBetweenCleanup) * time.Second)
	}
}

func (s *Server) setupHA() error {
	if hasDnsLB, err := s.staticConfig.DnsLoadBalancer.Check(); err != nil {
		return err
	} else if hasDnsLB {
		_, err := dnslbcfg.New(s.staticConfig.DnsLoadBalancer, s.logger)
		if err != nil {
			return err
		}
	}
	if s.staticConfig.Watchdog.CheckInterval > 0 {
		_, err := watchdog.New(s.staticConfig.Watchdog, s.logger)
		if err != nil {
			s.logger.Fatalln(err)
		}
	}
	return nil
}
