// Package conf parse config to configuration
package conf

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Config contains configuration items for sdk
type Config struct {
	TLSCAContext    []byte
	TLSKeyContext   []byte
	TLSCertContext  []byte
	PrivateKey      []byte
	NodesURL        []string
	PrivateKeyCurve string
	Group           string
	SMCrypto        bool
}

// ParseConfigFile parses the configuration from toml config file
func ParseConfigFile(cfgFile string) (*Config, error) {
	file, err := os.Open(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("open file failed, err: %v", err)
	}

	defer func() {
		err = file.Close()
		if err != nil {
			logrus.Fatalf("close file failed, err: %v", err)
		}
	}()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("file is not found, err: %v", err)
	}

	fileSize := fileInfo.Size()
	buffer := make([]byte, fileSize)

	_, err = file.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("read file failed, err: %v", err)
	}
	return ParseConfig(buffer)
}

// ParseConfig parses the configuration from []byte
func ParseConfig(buffer []byte) (*Config, error) {
	viper.SetConfigType("toml")
	viper.SetDefault("SMCrypto", false)
	viper.SetDefault("Network.Type", "rpc")
	viper.SetDefault("Network.CAFile", "ca.crt")
	viper.SetDefault("Network.Key", "sdk.key")
	viper.SetDefault("Network.Cert", "sdk.crt")
	viper.SetDefault("Network.CAContext", "")
	viper.SetDefault("Network.KeyContext", "")
	viper.SetDefault("Network.CertContext", "")
	err := viper.ReadConfig(bytes.NewBuffer(buffer))
	if err != nil {
		return nil, fmt.Errorf("viper .ReadConfig failed, err: %v", err)
	}
	config := new(Config)
	if viper.IsSet("Chain") {
		if viper.IsSet("Chain.Group") {
			config.Group = viper.GetString("Chain.Group")
		} else {
			return nil, fmt.Errorf("Chain.Group has not been set")
		}
		if viper.IsSet("Chain.SMCrypto") {
			config.SMCrypto = viper.GetBool("Chain.SMCrypto")
		} else {
			return nil, fmt.Errorf("SMCrypto has not been set")
		}
	} else {
		return nil, fmt.Errorf("chain has not been set")
	}
	if viper.IsSet("Account") {
		accountKeyFile := viper.GetString("Account.PrivateKeyFile")
		keyBytes, curve, err := LoadECPrivateKeyFromPEM(accountKeyFile)
		if err != nil {
			return nil, fmt.Errorf("parse private key failed, err: %v", err)
		}
		if config.SMCrypto && curve != Sm2p256v1 {
			return nil, fmt.Errorf("smcrypto must use sm2p256v1 private key, but found %s", curve)
		}
		if !config.SMCrypto && curve != Secp256k1 {
			return nil, fmt.Errorf("must use secp256k1 private key, but found %s", curve)
		}
		config.PrivateKey = keyBytes
		config.PrivateKeyCurve = curve
	} else {
		return nil, fmt.Errorf("network has not been set")
	}
	if viper.IsSet("Network") {
		CAFile := viper.GetString("Network.CAFile")
		KeyFile := viper.GetString("Network.Key")
		CertFile := viper.GetString("Network.Cert")
		config.TLSCAContext = []byte(viper.GetString("Network.CAContext"))
		config.TLSKeyContext = []byte(viper.GetString("Network.KeyContext"))
		config.TLSCertContext = []byte(viper.GetString("Network.CertContext"))
		if len(config.TLSCAContext) == 0 {
			config.TLSCAContext, err = ioutil.ReadFile(CAFile)
			if err != nil {
				panic(err)
			}
		}
		if len(config.TLSKeyContext) == 0 {
			config.TLSKeyContext, err = ioutil.ReadFile(KeyFile)
			if err != nil {
				panic(err)
			}
		}
		if len(config.TLSCertContext) == 0 {
			config.TLSCertContext, err = ioutil.ReadFile(CertFile)
			if err != nil {
				panic(err)
			}
		}
		if viper.IsSet("Network.NodesURL") {
			err := viper.UnmarshalKey("Network.NodesURL", &config.NodesURL)
			if err != nil {
				return nil, fmt.Errorf("parse Network.Connection failed. err: %v", err)
			}
		} else {
			return nil, fmt.Errorf("Network.NodesURL has not been set")
		}
	} else {
		return nil, fmt.Errorf("network has not been set")
	}
	return config, nil
}
