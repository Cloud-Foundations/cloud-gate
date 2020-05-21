package staticconfiguration

import (
	"bufio"
	"errors"
	"os"

	"github.com/Cloud-Foundations/cloud-gate/lib/constants"
	"gopkg.in/yaml.v2"
)

func getClusterSecretsFile(clusterSecretsFilename string) ([]string, error) {
	file, err := os.Open(clusterSecretsFilename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var rarray []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}
		rarray = append(rarray, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rarray) < 1 {
		return nil, errors.New("empty cluster secretFile")
	}
	return rarray, nil
}

func LoadVerifyConfigFile(configFilename string) (*StaticConfiguration, error) {
	var config StaticConfiguration
	config.Watchdog.SetDefaults()
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return nil, err
	}
	source, err := os.Open(configFilename)
	if err != nil {
		return nil, err
	}
	err = yaml.NewDecoder(source).Decode(&config)
	if err != nil {
		return nil, err
	}
	// setup defaults
	if config.Base.StatusPort == 0 {
		config.Base.StatusPort = constants.DefaultStatusPort
	}
	if config.Base.ServicePort == 0 {
		config.Base.ServicePort = constants.DefaultServicePort
	}
	if len(config.Base.AccountConfigurationUrl) == 0 {
		config.Base.AccountConfigurationUrl =
			constants.DefaultAccountConfigurationUrl
	}
	if config.Base.AccountConfigurationCheckInterval == 0 {
		config.Base.AccountConfigurationCheckInterval =
			constants.DefaultAccountConfigurationCheckInterval
	}
	// Verify oauth2 setup
	if len(config.OpenID.AuthURL) < 1 ||
		len(config.OpenID.TokenURL) < 1 ||
		len(config.OpenID.UserinfoURL) < 1 ||
		len(config.OpenID.Scopes) < 1 ||
		len(config.OpenID.ClientID) < 1 {
		return nil, errors.New("invalid openid config")
	}
	if err := config.setupHA(); err != nil {
		return nil, err
	}
	// Verify shared secrets
	if len(config.Base.ClusterSharedSecretFilename) < 0 {
		return nil, errors.New("missing shared cluster secrets")
	}
	config.Base.SharedSecrets, err = getClusterSecretsFile(
		config.Base.ClusterSharedSecretFilename)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func (config *StaticConfiguration) setupHA() error {
	if hasDnsLB, err := config.DnsLoadBalancer.Check(); err != nil {
		return err
	} else if hasDnsLB {
		config.DnsLoadBalancer.DoTLS = true
		if config.DnsLoadBalancer.TcpPort < 1 {
			config.DnsLoadBalancer.TcpPort = config.Base.StatusPort
		}
	}
	config.Watchdog.DoTLS = true
	if config.Watchdog.CheckInterval > 0 && config.Watchdog.TcpPort < 1 {
		config.Watchdog.TcpPort = config.Base.StatusPort
	}
	return nil
}
