package aws

import (
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/Cloud-Foundations/cloud-gate/broker"
	"github.com/Cloud-Foundations/cloud-gate/broker/configuration"
	"github.com/Cloud-Foundations/golib/pkg/auth/userinfo"
	"github.com/Cloud-Foundations/golib/pkg/log"
)

type userAllowedCredentialsCacheEntry struct {
	PermittedAccounts []broker.PermittedAccount
	Expiration        time.Time
}

type accountRoleCacheEntry struct {
	Roles       []string
	Expiration  time.Time
	LastBadTime time.Time
}

type awsProfileEntry struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
}

const defaultListRolesRoleName = "CPEBrokerRole"

type Broker struct {
	config                      *configuration.Configuration
	userInfo                    userinfo.UserGroupsGetter
	rawUserInfo                 userinfo.UserGroupsGetter
	credentialsFilename         string
	logger                      log.DebugLogger
	auditLogger                 log.DebugLogger
	masterStsClient             *sts.Client
	masterStsRegion             string
	userAllowedCredentialsCache map[string]userAllowedCredentialsCacheEntry
	userAllowedCredentialsMutex sync.Mutex
	accountRoleCache            map[string]accountRoleCacheEntry // K: acc. name
	accountRoleMutex            sync.Mutex
	isUnsealedChannel           chan error
	profileCredentials          map[string]awsProfileEntry // Key: profile name
	rawCredentialsFile          []byte
	listRolesRoleName           string
	listRolesSemaphore          *semaphore.Weighted
}

func New(userInfo userinfo.UserGroupsGetter, credentialsFilename string,
	listRolesRoleName string, logger log.DebugLogger,
	auditLogger log.DebugLogger) *Broker {
	return newBroker(userInfo, credentialsFilename, listRolesRoleName, logger,
		auditLogger)
}

func (b *Broker) UpdateConfiguration(
	config *configuration.Configuration) error {
	return b.updateConfiguration(config)
}

func (b *Broker) GetUserAllowedAccounts(username string) ([]broker.PermittedAccount, error) {
	return b.getUserAllowedAccounts(username)
}

func (b *Broker) IsUserAllowedToAssumeRole(username string, accountName string, roleName string) (bool, error) {
	return b.isUserAllowedToAssumeRole(username, accountName, roleName)
}

func (b *Broker) GetConsoleURLForAccountRole(accountName string, roleName string, userName string, issuerURL string) (string, error) {
	return b.getConsoleURLForAccountRole(accountName, roleName, userName, issuerURL)
}

func (b *Broker) GenerateTokenCredentials(accountName string, roleName string, userName string) (*broker.AWSCredentialsJSON, error) {
	return b.generateTokenCredentials(accountName, roleName, userName)
}

func (b *Broker) ProcessNewUnsealingSecret(secret string) (ready bool, err error) {
	return b.processNewUnsealingSecret(secret)
}

func (b *Broker) GetIsUnsealedChannel() (<-chan error, error) {
	return b.isUnsealedChannel, nil
}

func (b *Broker) LoadCredentialsFile() error {
	return b.loadCredentialsFile()
}
