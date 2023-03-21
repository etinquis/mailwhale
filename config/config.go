package config

import (
	"errors"
	"flag"
	"fmt"
	"github.com/emvi/logbuch"
	"github.com/jinzhu/configor"
	"github.com/muety/mailwhale/types"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
)

const (
	KeyUser   = "user"
	KeyClient = "client"
)

type EmailPasswordTuple struct {
	Email    string
	Password string
}

type mailConfig struct {
	Domain          string `yaml:"domain" env:"MW_MAIL_DOMAIN"`
	SystemSenderTpl string `yaml:"system_sender" env:"MW_MAIL_SYSTEM_SENDER" default:"MailWhale System <system@{0}>"`
}

type smtpConfig struct {
	Host          string `env:"MW_SMTP_HOST"`
	Port          uint   `env:"MW_SMTP_PORT"`
	Username      string `env:"MW_SMTP_USER"`
	Password      string `env:"MW_SMTP_PASS"`
	TLS           bool   `env:"MW_SMTP_TLS"`
	SkipVerifyTLS bool   `yaml:"skip_verify_tls" env:"MW_SMTP_SKIP_VERIFY_TLS"`
}

type webConfig struct {
	ListenV4    string   `yaml:"listen_v4" env:"MW_WEB_LISTEN_V4"` // deprecated, use ListenAddr
	ListenAddr  string   `yaml:"listen_addr" default:"127.0.0.1:3000" env:"MW_WEB_LISTEN_ADDR"`
	CorsOrigins []string `yaml:"cors_origins" env:"MW_WEB_CORS_ORIGINS"`
	PublicUrl   string   `yaml:"public_url" default:"http://localhost:3000" env:"MW_WEB_PUBLIC_URL"`
}

type storeConfig struct {
	Path string `default:"data.json.db" env:"MW_STORE_PATH"`
}

type securityConfig struct {
	Pepper          string   `env:"MW_SECURITY_PEPPER"`
	AllowSignup     bool     `yaml:"allow_signup" env:"MW_SECURITY_ALLOW_SIGNUP" default:"true"`
	VerifySenders   bool     `yaml:"verify_senders" default:"true" env:"MW_SECURITY_VERIFY_SENDERS"`
	VerifyUsers     bool     `yaml:"verify_users" default:"true" env:"MW_SECURITY_VERIFY_USERS"`
	BlockList       []string `yaml:"block_list" env:"MW_SECURITY_BLOCK_LIST"`
	blockListParsed BlockList
}

type BlockList []*regexp.Regexp

type Config struct {
	Env      string `default:"dev" env:"MW_ENV"`
	Version  string
	Mail     mailConfig
	Web      webConfig
	Smtp     smtpConfig
	Store    storeConfig
	Security securityConfig
}

var cfg *Config

func Get() *Config {
	return cfg
}

func Set(config *Config) {
	cfg = config
}

func Load() *Config {
	config := &Config{}

	configfile := flag.String("config.file", os.Getenv("MW_CONFIG_FILE"), "path to configuration file")
	flag.StringVar(&config.Env, "env", "dev", "whether to use development- or production settings")
	flag.StringVar(&config.Mail.Domain, "mail.domain", "", "default domain for sending mails")
	flag.StringVar(&config.Web.ListenAddr, "web.listen_addr", "", "IP and port for the web server to listen on (can be IPv4 or IPv6)")
	// flag.Var(&config.Web.CorsOrigins, "web.cors_origin", "list of URLs which to accept CORS requests for")
	flag.StringVar(&config.Web.PublicUrl, "web.public_url", "http://localhost:3000", "the URL under which your MailWhale server is available from the public internet")
	flag.StringVar(&config.Smtp.Host, "smtp.host", "", "SMTP relay host name or IP")
	flag.UintVar(&config.Smtp.Port, "smtp.port", 0, "SMTP relay port")
	flag.StringVar(&config.Smtp.Username, "smtp.username", "", "SMTP relay authentication user name")
	flag.StringVar(&config.Smtp.Password, "smtp.password", "", "SMTP relay authentication password")
	flag.BoolVar(&config.Smtp.TLS, "smtp.tls", false, "whether to require full TLS (not to be confused with STARTTLS) for the SMTP relay")
	flag.BoolVar(&config.Smtp.SkipVerifyTLS, "smtp.skip_verify_tls", false, "whether to skip certificate verification (e.g. trust self-signed certs)")
	flag.StringVar(&config.Store.Path, "store.path", "data.json.db", "target location of the database file")
	flag.StringVar(&config.Security.Pepper, "security.pepper", "", "pepper to use for hashing user passwords")
	flag.BoolVar(&config.Security.AllowSignup, "security.allow_signup", true, "whether to allow the registration of new users")
	flag.BoolVar(&config.Security.VerifyUsers, "security.verify_users", true, "whether to require new users to activate their account using a confirmation mail")
	flag.BoolVar(&config.Security.VerifySenders, "security.verify_senders", true, "whether to validate sender addresses and their domains' SPF records")
	// flag.Var(&config.Security.BlockList, "security.verify_senders", "list of regexes used to block certain recipient addresses")

	flag.Parse() // the only value we really need right now is config.file, we will re-parse after loading config in order to favor values set on the command line over values read from config file or env vars

	if *configfile == "" {
		*configfile = "config.yml"
	}

	logbuch.Info("Reading config from: %v", *configfile)

	if err := configor.New(&configor.Config{}).Load(config, *configfile); err != nil {
		logbuch.Fatal("failed to read config: %v", err)
	}

	flag.Parse()

	config.Version = readVersion()

	if config.Web.ListenV4 != "" {
		config.Web.ListenAddr = config.Web.ListenV4 // for backwards-compatbility
	}

	if config.Web.ListenAddr == "" {
		logbuch.Fatal("config option 'listen_addr' must be specified")
	}

	if !config.Mail.SystemSender().Valid() {
		logbuch.Fatal("system sender address is invalid")
	}

	logbuch.Info("---")
	logbuch.Info("This instance is assumed to be publicly accessible at: %v", config.Web.GetPublicUrl())
	logbuch.Info("User registration enabled: %v", config.Security.AllowSignup)
	logbuch.Info("Account activation required: %v", config.Security.VerifyUsers)
	logbuch.Info("Sender address verification required: %v", config.Security.VerifySenders)
	logbuch.Info("Blocked recipient patterns: %d", len(config.Security.BlockListPatterns()))
	logbuch.Info("---")

	Set(config)
	return Get()
}

func (c *webConfig) GetPublicUrl() string {
	return strings.TrimSuffix(c.PublicUrl, "/")
}

func (c *smtpConfig) ConnStr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func (c *mailConfig) SystemSender() types.MailAddress {
	return types.MailAddress(strings.Replace(c.SystemSenderTpl, "{0}", c.Domain, -1))
}

func (c *securityConfig) BlockListPatterns() BlockList {
	if len(c.BlockList) != len(c.blockListParsed) {
		for _, r := range c.BlockList {
			if p, err := regexp.Compile(r); err == nil {
				c.blockListParsed = append(c.blockListParsed, p)
			} else {
				logbuch.Error("failed to parse block list pattern '%s': %v", err)
			}
		}
	}
	return c.blockListParsed
}

func (c *Config) IsDev() bool {
	return c.Env == "dev" || c.Env == "development"
}

func (l BlockList) Check(email string) error {
	for _, p := range l {
		if p.MatchString(email) {
			return errors.New(fmt.Sprintf("recipient '%s' blocked by the server", email))
		}
	}
	return nil
}

func (l BlockList) CheckBatch(emails []string) error {
	for _, e := range emails {
		if err := l.Check(e); err != nil {
			return err
		}
	}
	return nil
}

func readVersion() string {
	file, err := os.Open("version.txt")
	if err != nil {
		logbuch.Fatal("failed to read version: %v", err)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		logbuch.Fatal(err.Error())
	}

	return strings.TrimSpace(string(bytes))
}
