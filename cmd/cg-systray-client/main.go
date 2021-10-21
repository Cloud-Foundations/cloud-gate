package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v2"

	"github.com/getlantern/systray"
)

const defaultVersionNumber = "No version provided"
const userAgentAppName = "cloud_gate_cli"

var (
	// Must be a global variable in the data segment so that the build
	// process can inject the version number on the fly when building the
	// binary. Use only from the Usage() function.
	Version         = defaultVersionNumber
	DefaultBaseURL  = ""
	userAgentString = userAgentAppName
)

const defaultOutputProfilePrefix = ""

var (
	certFilename = flag.String("cert", filepath.Join(getUserHomeDir(), ".ssl", "keymaster.cert"), "A PEM eoncoded certificate file.")
	keyFilename  = flag.String("key", filepath.Join(getUserHomeDir(), ".ssl", "keymaster.key"), "A PEM encoded private key file.")
	baseURL      = flag.String("baseURL", DefaultBaseURL,
		"location of the cloud-broker")
	noSystray            = flag.Bool("noSystray", false, "No systray, just background loop")
	crededentialFilename = flag.String("credentialFile", filepath.Join(getUserHomeDir(), ".aws", "credentials"), "An Ini file with credentials")
	askAdminRoles        = flag.Bool("askAdminRoles", false, "ask also for admin roles")
	outputProfilePrefix  = flag.String("outputProfilePrefix", defaultOutputProfilePrefix, "prefix to put to profile names $PREFIX$accountName-$roleName")
	lowerCaseProfileName = flag.Bool("lowerCaseProfileName", false, "set profile names to lowercase")
	configFilename       = flag.String("configFile", filepath.Join(getUserHomeDir(), ".config", "cloud-gate", "config.yml"), "A YAML file with cloud-gate config")
	oldBotoCompat        = flag.Bool("oldBotoCompat", false, "add aws_security_token for OLD boto installations (not recommended)")
	includeRoleREFilter  = flag.String("includeRoleREFilter", "", "Positive RE filter that role/account MUST match")
	excludeRoleREFilter  = flag.String("excludeRoleREFilter", "", "Negative RE filter. Acount/Role values matching will not be generated")
	logLevel             = flag.Uint("logLevel", 1, "Verbosity of logging")
	logFilename          = flag.String("logFilename", "cloudgate-systray.log", "The filename where los will be appended")
)

const (
	StatusFail = iota
	StatusWarn
	StatusGood
)

type AppConfigFile struct {
	BaseURL              string `yaml:"base_url"`
	OutputProfilePrefix  string `yaml:"output_profile_prefix"`
	LowerCaseProfileName bool   `yaml:"lower_case_profile_name"`
	IncludeRoleREFilter  string `yaml:"include_role_re_filter"`
	ExcludeRoleREFilter  string `yaml:"exclude_role_re_filter"`
	CertFilename         string `yaml:"cert_filename"`
	KeyFilename          string `yaml:"key_filename"`
}

type cloudAccountInfo struct {
	Name           string
	AvailableRoles []string
}

type getAccountInfo struct {
	AuthUsername  string
	CloudAccounts map[string]cloudAccountInfo
}

type AWSCredentialsJSON struct {
	SessionId    string    `json:"sessionId"`
	SessionKey   string    `json:"sessionKey"`
	SessionToken string    `json:"sessionToken"`
	Region       string    `json:"region,omitempty"`
	Expiration   time.Time `json:"cloudgate_comment_expiration,omitempty"`
}

type cgClient struct {
	config               AppConfigFile
	logLevel             uint
	logger               *log.Logger
	excludeRoleRE        *regexp.Regexp
	includeRoleRE        *regexp.Regexp
	lowerCaseProfileName bool
	oldBotoCompat        bool
	appMessageChan       chan string
	statusIconChan       chan int
	getCredsNowChan      chan bool
}

func (c *cgClient) LoggerPrintf(level uint, format string, v ...interface{}) {
	if level <= c.logLevel {
		c.logger.Printf(format, v...)
	}
}

func (c *cgClient) loggerPrintf(level uint, format string, v ...interface{}) {
	if level <= c.logLevel {
		c.logger.Printf(format, v...)
		c.appMessageChan <- fmt.Sprintf(format, v...)
	}
}

// since we start channel consumption after startup we need to have some buffer...
// This is not great story
const defaultChanSize = 6

func NewClient(config AppConfigFile, excludeRoleRE *regexp.Regexp, includeRoleRE *regexp.Regexp, lowerCaseProfileName bool, logLevel uint, logger *log.Logger) *cgClient {
	client := cgClient{
		config:               config,
		excludeRoleRE:        excludeRoleRE,
		includeRoleRE:        includeRoleRE,
		lowerCaseProfileName: lowerCaseProfileName,
		logLevel:             logLevel,
		logger:               logger,
		appMessageChan:       make(chan string, defaultChanSize),
		statusIconChan:       make(chan int, defaultChanSize),
		getCredsNowChan:      make(chan bool, defaultChanSize),
	}
	return &client
}

func loadVerifyConfigFile(filename string) (AppConfigFile, error) {
	var config AppConfigFile
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		err = saveDefaultConfig(filename)
		if err != nil {
			return config, err
		}
	}
	source, err := ioutil.ReadFile(filename)
	if err != nil {
		err = errors.New("cannot read config file")
		return config, err
	}
	err = yaml.Unmarshal(source, &config)
	if err != nil {
		err = errors.New("Cannot parse config file")
		return config, err
	}

	if len(config.BaseURL) < 1 {
		err = errors.New("Invalid Config file... no place get the credentials")
		return config, err
	}
	// TODO: ensure all enpoints are https urls
	return config, nil
}

func saveDefaultConfig(configFilename string) error {
	os.MkdirAll(filepath.Dir(configFilename), 0755)
	config := AppConfigFile{
		BaseURL:              *baseURL,
		OutputProfilePrefix:  defaultOutputProfilePrefix,
		LowerCaseProfileName: false,
	}
	configBytes, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(configFilename, configBytes, 0644)

}

const badReturnErrText = "bad return code"
const sleepDuration = 1800 * time.Second
const failureSleepDuration = 60 * time.Second

func (c *cgClient) getAndUpdateCreds(client *http.Client, accountName, roleName string,
	cfg *ini.File, outputProfilePrefix string) error {
	c.loggerPrintf(1, "Getting creds for account=%s, role=%s", accountName, roleName)

	values := url.Values{"accountName": {accountName}, "roleName": {roleName}}
	req, err := http.NewRequest("POST", c.config.BaseURL+"/generatetoken", strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgentString)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return errors.New(badReturnErrText)
	}

	var awsCreds AWSCredentialsJSON
	err = json.Unmarshal(data, &awsCreds)
	if err != nil {
		return err
	}
	fileProfile := outputProfilePrefix + accountName + "-" + roleName
	if c.lowerCaseProfileName {
		fileProfile = strings.ToLower(fileProfile)
	}
	cfg.Section(fileProfile).Key("aws_access_key_id").SetValue(awsCreds.SessionId)
	cfg.Section(fileProfile).Key("aws_secret_access_key").SetValue(awsCreds.SessionKey)
	cfg.Section(fileProfile).Key("aws_session_token").SetValue(awsCreds.SessionToken)
	if c.oldBotoCompat {
		cfg.Section(fileProfile).Key("aws_security_token").SetValue(awsCreds.SessionToken)
	} else {
		cfg.Section(fileProfile).DeleteKey("aws_security_token")
	}
	if !awsCreds.Expiration.IsZero() {
		cfg.Section(fileProfile).Key("token_expiration").SetValue(awsCreds.Expiration.UTC().Format(time.RFC3339))
	} else {
		cfg.Section(fileProfile).DeleteKey("token_expiration")
	}

	return nil
}

func getParseURLEnvVariable(name string) (*url.URL, error) {
	envVariable := os.Getenv(name)
	if len(envVariable) < 1 {
		return nil, nil
	}
	envURL, err := url.Parse(envVariable)
	if err != nil {
		return nil, err
	}

	return envURL, nil
}

func setupCredentialFile(credentialFilename string) (*ini.File, error) {
	// Create file if it does not exist
	if _, err := os.Stat(credentialFilename); os.IsNotExist(err) {
		os.MkdirAll(filepath.Dir(credentialFilename), 0770)
		file, err := os.OpenFile(credentialFilename, os.O_RDONLY|os.O_CREATE, 0660)
		if err != nil {
			return nil, err
		}
		file.Close()
	}

	return ini.Load(credentialFilename)
}

func setupHttpClient(cert tls.Certificate) (*http.Client, error) {
	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}

	// proxy env variables in ascending order of preference, lower case 'http_proxy' dominates
	// just like curl
	proxyEnvVariables := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy"}
	for _, proxyVar := range proxyEnvVariables {
		httpProxy, err := getParseURLEnvVariable(proxyVar)
		if err == nil && httpProxy != nil {
			transport.Proxy = http.ProxyURL(httpProxy)
		}
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	return client, nil
}

func (c *cgClient) getAccountsList(client *http.Client) (*getAccountInfo, error) {
	c.loggerPrintf(4, "Top of getAcountsList")
	// Do GET something
	req, err := http.NewRequest("GET", c.config.BaseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgentString)
	resp, err := client.Do(req)
	if err != nil {
		c.logger.Printf("failed to connect err=%s transport=%+v ", err, client.Transport)
		if resp != nil {
			c.logger.Printf("resp=+%v", resp)
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			c.logger.Printf("getAccountsList, Failed Unauthorized, Please check your certificate configuration.")
		}
		return nil, fmt.Errorf("getAccountsList: Failed to Get accounts Status=%d", resp.StatusCode)
	}

	// Dump response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var accountList getAccountInfo
	err = json.Unmarshal(data, &accountList)
	if err != nil {
		c.logger.Printf("Error decoding account Data, data=%s", data)
		return nil, err
	}
	c.loggerPrintf(2, "accountList=%v", accountList)
	return &accountList, nil

}

func (c *cgClient) getCerts(cert tls.Certificate, baseUrl string,
	credentialFilename string, askAdminRoles bool,
	outputProfilePrefix string,
	includeRoleRE *regexp.Regexp, excludeRoleRE *regexp.Regexp) (int, error) {

	c.loggerPrintf(4, "Top of getCerts")
	credFile, err := setupCredentialFile(credentialFilename)
	if err != nil {
		return 0, fmt.Errorf("getCerts error from CredentialFile: %s", err)
	}

	client, err := setupHttpClient(cert)
	if err != nil {
		return 0, err
	}
	accountList, err := c.getAccountsList(client)
	if err != nil {
		return 0, err
	}

	credentialsGenerated := 0
	for _, account := range accountList.CloudAccounts {
		for _, roleName := range account.AvailableRoles {
			adminRole, err := regexp.Match("(?i)admin", []byte(roleName))
			if adminRole && !askAdminRoles {
				continue
			}
			if err != nil {
				log.Fatalf("error on regexp=%s", err)
			}
			computedName := account.Name + "-" + roleName
			if includeRoleRE != nil {
				if !includeRoleRE.Match([]byte(computedName)) {
					continue
				}
			}
			if excludeRoleRE != nil {
				if excludeRoleRE.Match([]byte(computedName)) {
					continue
				}
			}
			err = c.getAndUpdateCreds(client,
				account.Name, roleName, credFile,
				outputProfilePrefix)
			if err != nil {
				if err.Error() == badReturnErrText {
					c.logger.Printf("skipping role")
					continue
				}
				c.logger.Printf("error on getAnd UpdateCreds=%s", err)
				return credentialsGenerated, err
			}
			credentialsGenerated += 1
		}
	}
	err = credFile.SaveTo(credentialFilename)
	if err != nil {
		return credentialsGenerated, err
	}

	return credentialsGenerated, nil
}

//Assumes cert is pem ecoded
func getCertExpirationTime(certFilename string) (time.Time, error) {
	dat, err := ioutil.ReadFile(certFilename)
	if err != nil {
		return time.Now(), err
	}
	block, _ := pem.Decode(dat)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Now(), err
	}
	return cert.NotAfter, nil
}

func getUserHomeDir() (homeDir string) {
	homeDir = os.Getenv("HOME")
	if homeDir != "" {
		return homeDir
	}
	usr, err := user.Current()
	if err != nil {
		return homeDir
	}
	// TODO: verify on Windows... see: http://stackoverflow.com/questions/7922270/obtain-users-home-directory
	homeDir = usr.HomeDir
	return
}

func computeUserAgent() {
	uaVersion := Version
	if Version == defaultVersionNumber {
		uaVersion = "0.0"
	}

	userAgentString = fmt.Sprintf("%s/%s (%s %s)", userAgentAppName, uaVersion, runtime.GOOS, runtime.GOARCH)
}

func usage() {
	fmt.Fprintf(
		os.Stderr, "Usage of %s (version %s):\n", os.Args[0], Version)
	flag.PrintDefaults()
}

func (c *cgClient) withCertFetchCredentials(config AppConfigFile, cert tls.Certificate, includeRoleRE *regexp.Regexp, excludeRoleRE *regexp.Regexp) error {
	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		c.loggerPrintf(0, "Error Parsing Certificate: %s", err)
		return err
	}
	requestAdmin := *askAdminRoles
	for parsedCert.NotAfter.After(time.Now()) {
		credentialCount, err := c.getCerts(cert, config.BaseURL, *crededentialFilename,
			requestAdmin, config.OutputProfilePrefix,
			includeRoleRE, excludeRoleRE)
		if err != nil {
			c.logger.Printf("err=%s", err)
			c.loggerPrintf(0, "Failure getting certs, retrying in (%s)", failureSleepDuration)
			c.statusIconChan <- StatusWarn
			time.Sleep(failureSleepDuration)
			continue
		}
		c.statusIconChan <- StatusGood
		requestAdmin = *askAdminRoles
		c.loggerPrintf(0, "%d credentials successfully generated. Sleeping until (%s)", credentialCount, time.Now().Add(sleepDuration).Format(time.RFC822))
		select {
		case <-time.After(sleepDuration):
			c.loggerPrintf(1, "Timer expired")
		case getAdmin := <-c.getCredsNowChan:
			requestAdmin = getAdmin
			c.loggerPrintf(1, "Got message for immediate request")
		}

	}
	return nil
}

// This function never ends except for a panic
func (c *cgClient) BackgroundLoop(config AppConfigFile, certFilename string, keyFilename string, includeRoleRE *regexp.Regexp, excludeRoleRE *regexp.Regexp) error {
	for true {
		//step 1: load credentials
		c.loggerPrintf(2, "Top of  backgroundLoop")
		cert, err := tls.LoadX509KeyPair(certFilename, keyFilename)
		if err != nil {
			c.loggerPrintf(0, "Error Loading X509KeyPair: %s", err)
			time.Sleep(2 * time.Second)
			continue
		}
		c.loggerPrintf(2, "Certificalte loaded")
		parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			c.loggerPrintf(0, "Error Parsing Certificate: %s", err)
			time.Sleep(2 * time.Second)
			continue
		}
		c.loggerPrintf(2, "Certificalte parsed")
		if parsedCert.NotAfter.Before(time.Now()) {
			c.loggerPrintf(0, "Certificalte is expired")
			//loggerPrintf(0, "keymaster certificate is expired, please run keymaster binary. Certificate expired at %s", parsedCert.NotAfter)
			time.Sleep(2 * time.Second)
			continue
		}
		c.loggerPrintf(0, "Certificalte is not expired exp=%s", parsedCert.NotAfter)

		time.Sleep(2 * time.Second)
		err = c.withCertFetchCredentials(config, cert, includeRoleRE, excludeRoleRE)
		if err != nil {
			c.loggerPrintf(0, "Error Fetching Credentials: %s", err)
			time.Sleep(10 * time.Second)
			continue
		}
		time.Sleep(5 * time.Second)
		c.loggerPrintf(0, "End of  backgroundLoop")

	}
	return nil
}

func (c *cgClient) OnReady() {
	systray.SetTooltip("CloudGate systray")
	mAppMessage := systray.AddMenuItem("status", "CurrentMessage")
	subMenuTop := systray.AddMenuItem("Get Credentials Now", "Get Credentials Immediately")
	subMenuGetRegularCreds := subMenuTop.AddSubMenuItem("Regular", "Requests Credentials now, dont wait for timer")
	subMenuGetAdminCreds := subMenuTop.AddSubMenuItem("Admin (sudo)", "Immediately request admin credentials (1h) ")
	mQuitOrig := systray.AddMenuItem("Quit", "Quit the whole app")
	go func() {
		for {
			select {
			case <-subMenuGetAdminCreds.ClickedCh:
				c.getCredsNowChan <- true
				subMenuGetAdminCreds.Disable()
			case <-subMenuGetRegularCreds.ClickedCh:
				c.getCredsNowChan <- false
				subMenuGetRegularCreds.Disable()
			case <-mQuitOrig.ClickedCh:
				fmt.Println("Requesting quit")
				systray.Quit()
				fmt.Println("Finished quitting")
			}
		}
	}()
	go func() {
		for {
			//var message string
			message := <-c.appMessageChan
			mAppMessage.SetTitle(message)
		}
	}()
	//icon func
	go func() {
		systray.SetIcon(getIcon("favicon.ico"))
		mAppMessage.SetIcon(getIcon("exclamation-32x32.png"))
		for {
			appStatus := <-c.statusIconChan
			subMenuGetAdminCreds.Enable()
			subMenuGetRegularCreds.Enable()
			switch appStatus {
			case StatusGood:
				mAppMessage.SetIcon(getIcon("checkmark-32x32.png"))
			default:
				mAppMessage.SetIcon(getIcon("crossmark-32x32.png"))
			}
		}
	}()
}

func (c *cgClient) OnExit() {
	now := time.Now()
	ioutil.WriteFile(fmt.Sprintf(`on_exit_%d.txt`, now.UnixNano()), []byte(now.String()), 0644)
}

func (c *cgClient) ConsumeChannels() {
	go func() {
		for {
			<-c.appMessageChan

		}
	}()
	for {
		<-c.statusIconChan
	}

}

func getIcon(s string) []byte {
	data, err := Asset("data/" + s)
	if err != nil {
		fmt.Print(err)
	}
	return data
}

func (c *cgClient) OneShotCLIPath(config AppConfigFile, certFilename string, keyFilename string, includeRoleRE *regexp.Regexp, excludeRoleRE *regexp.Regexp) error {
	certNotAfter, err := getCertExpirationTime(certFilename)
	if err != nil {
		log.Fatalf("Error on getCertExpirationTime: %s", err)
	}
	if certNotAfter.Before(time.Now()) {
		log.Fatalf("keymaster certificate is expired, please run keymaster binary. Certificate expired at %s", certNotAfter)
	}

	for certNotAfter.After(time.Now()) {
		cert, err := tls.LoadX509KeyPair(certFilename, keyFilename)
		if err != nil {
			log.Fatalf("Error Loading X509KeyPair: %s", err)
		}
		credentialCount, err := c.getCerts(cert, config.BaseURL, *crededentialFilename,
			*askAdminRoles, config.OutputProfilePrefix,
			includeRoleRE, excludeRoleRE)
		if err != nil {
			log.Printf("err=%s", err)
			log.Printf("Failure getting certs, retrying in (%s)", failureSleepDuration)
			time.Sleep(failureSleepDuration)
		} else {
			log.Printf("%d credentials successfully generated. Sleeping for (%s)", credentialCount, sleepDuration)
			time.Sleep(sleepDuration)
		}
		certNotAfter, err = getCertExpirationTime(certFilename)
		if err != nil {
			log.Fatal(err)
		}

	}

	log.Printf("done")

	return nil

}

//func initalizeLogger()

func main() {
	flag.Usage = usage
	flag.Parse()
	computeUserAgent()

	logFile, err := os.OpenFile(*logFilename,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to openfile =%s", err)
	}
	defer logFile.Close()
	fileLogger := log.New(logFile, "", log.LstdFlags)

	config, err := loadVerifyConfigFile(*configFilename)
	if err != nil {
		log.Fatal(err)
	}
	if *outputProfilePrefix != defaultOutputProfilePrefix {
		config.OutputProfilePrefix = *outputProfilePrefix
	}
	// Because we want to display a sensible error message when using flags
	// and we cannot tell using the flags package if a value has been modified
	// we compare the processed value with the default so that any non-default
	// value entered on the cli overrides the values in the config.
	if *certFilename == filepath.Join(getUserHomeDir(), ".ssl", "keymaster.cert") {
		if config.CertFilename != "" {
			*certFilename = config.CertFilename
		}
	}
	if *keyFilename == filepath.Join(getUserHomeDir(), ".ssl", "keymaster.key") {
		if config.KeyFilename != "" {
			*keyFilename = config.KeyFilename
		}
	}

	var includeRoleRE *regexp.Regexp
	if *includeRoleREFilter != "" {
		config.IncludeRoleREFilter = *includeRoleREFilter
	}
	if config.IncludeRoleREFilter != "" {
		includeRoleRE, err = regexp.Compile(config.IncludeRoleREFilter)
		if err != nil {
			log.Fatal(err)
		}
	}
	var excludeRoleRE *regexp.Regexp
	if *excludeRoleREFilter != "" {
		config.ExcludeRoleREFilter = *excludeRoleREFilter
	}
	if config.ExcludeRoleREFilter != "" {
		excludeRoleRE, err = regexp.Compile(config.ExcludeRoleREFilter)
		if err != nil {
			log.Fatal(err)
		}
	}
	if *baseURL != DefaultBaseURL {
		config.BaseURL = *baseURL
	}

	client := NewClient(config, excludeRoleRE, includeRoleRE, *lowerCaseProfileName, *logLevel, fileLogger)

	client.LoggerPrintf(1, "Configuration Loaded")
	client.LoggerPrintf(2, "config=%+v", config)
	client.LoggerPrintf(2, "Using Cert=%s, key=%s", *certFilename, *keyFilename)

	useNew := true
	if !useNew {
		err = client.OneShotCLIPath(config, *certFilename, *keyFilename, includeRoleRE, excludeRoleRE)
		if err != nil {
			log.Fatalf("Fatal one shoe exec: %s", err)
		}
		log.Printf("done")
		return
	}
	//start background thread
	go func() {
		err = client.BackgroundLoop(config, *certFilename, *keyFilename, includeRoleRE, excludeRoleRE)
		if err != nil {
			log.Fatalf("Fatal one shoe exec: %s", err)
		}
	}()

	if *noSystray {
		client.ConsumeChannels()
	} else {
		systray.Run(client.OnReady, client.OnExit)
	}
	log.Printf("done?")

}
