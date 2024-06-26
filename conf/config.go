// Package conf parse config to configuration
package conf

import (
	"fmt"
	"log"
	"strconv"

	"github.com/spf13/viper"
)

// Config contains configuration items for sdk
type Config struct {
	IsHTTP         bool
	ChainID        string
	ConfigFile     string
	CAFile         string
	TLSCAContext   []byte
	Key            string
	TLSKeyContext  []byte
	Cert           string
	TLSCertContext []byte
	IsSMCrypto     bool
	PrivateKey     []byte
	GroupID        string
	NodeURL        string
	Host           string
	Port           int
}

// ParseConfigFile parses the configuration from toml config file
func ParseConfigFile(cfgFile string) ([]Config, error) {
	//file, err := os.Open(cfgFile)
	//if err != nil {
	//	return nil, fmt.Errorf("open file failed, err: %v", err)
	//}
	//
	//defer func() {
	//	err = file.Close()
	//	if err != nil {
	//		logrus.Fatalf("close file failed, err: %v", err)
	//	}
	//}()
	//
	//fileInfo, err := file.Stat()
	//if err != nil {
	//	return nil, fmt.Errorf("file is not found, err: %v", err)
	//}
	//
	//fileSize := fileInfo.Size()
	//buffer := make([]byte, fileSize)
	//
	//_, err = file.Read(buffer)
	//if err != nil {
	//	return nil, fmt.Errorf("read file failed, err: %v", err)
	//}
	return ParseConfig(cfgFile)
}

// ParseConfig parses the configuration from []byte
func ParseConfig(cfgFile string) ([]Config, error) {
	//viper.SetConfigType("toml")
	viper.SetDefault("SMCrypto", false)
	viper.SetConfigFile(cfgFile)
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal(err)
	}
	//err := viper.ReadConfig(bytes.NewBuffer(buffer))
	//if err != nil {
	//	return nil, fmt.Errorf("viper .ReadConfig failed, err: %v", err)
	//}
	config := new(Config)
	var configs []Config

	if viper.IsSet("Chain.ChainID") {
		if viper.IsSet("Chain.ChainID") {
			config.ChainID = viper.GetString("Chain.ChainID")
		} else {
			return nil, fmt.Errorf("Chain.ChainID has not been set")
		}
		if viper.IsSet("Chain.SMCrypto") {
			config.IsSMCrypto = viper.GetBool("Chain.SMCrypto")
		} else {
			return nil, fmt.Errorf("SMCrypto has not been set")
		}
	} else {
		return nil, fmt.Errorf("chain has not been set")
	}
	if viper.IsSet("Account.KeyFile") {
		accountKeyFile := viper.GetString("Account.KeyFile")
		keyBytes, curve, err := LoadECPrivateKeyFromPEM(accountKeyFile)
		if err != nil {
			return nil, fmt.Errorf("parse private key failed, err: %v", err)
		}
		if config.IsSMCrypto && curve != sm2p256v1 {
			return nil, fmt.Errorf("smcrypto must use sm2p256v1 private key, but found %s", curve)
		}
		if !config.IsSMCrypto && curve != secp256k1 {
			return nil, fmt.Errorf("must use secp256k1 private key, but found %s", curve)
		}
		config.PrivateKey = keyBytes
	} else {
		return nil, fmt.Errorf("network has not been set")
	}
	if viper.IsSet("Group.GroupID") {
		config.GroupID = viper.GetString("Group.GroupID")
	}
	config.ConfigFile = cfgFile
	for i := 0; ; i++ {
		if viper.IsSet("peers.node." + strconv.Itoa(i)) {
			nodeURL := viper.GetString("peers.node." + strconv.Itoa(i))
			fmt.Println(nodeURL)
			fmt.Println(len(nodeURL))
			configs = append(configs, *config)
			configs[i].NodeURL = nodeURL
		} else {
			break
		}
	}
	//if viper.IsSet("Network.Connection") {
	//connectionType := viper.GetString("Network.Type")
	//if strings.EqualFold(connectionType, "rpc") {
	//	config.IsHTTP = true
	//} else if strings.EqualFold(connectionType, "channel") {
	//	config.IsHTTP = false
	//} else {
	//	logrus.Printf("Network.Type %s is not supported, use channel", connectionType)
	//}
	//config.CAFile = viper.GetString("Network.CAFile")
	//config.Key = viper.GetString("Network.Key")
	//config.Cert = viper.GetString("Network.Cert")
	//config.TLSCAContext = []byte(viper.GetString("Network.CAContext"))
	//config.TLSKeyContext = []byte(viper.GetString("Network.KeyContext"))
	//config.TLSCertContext = []byte(viper.GetString("Network.CertContext"))
	//if len(config.TLSCAContext) == 0 {
	//	config.TLSCAContext, err = ioutil.ReadFile(config.CAFile)
	//	if err != nil {
	//		panic(err)
	//	}
	//}
	//if len(config.TLSKeyContext) == 0 {
	//	config.TLSKeyContext, err = ioutil.ReadFile(config.Key)
	//	if err != nil {
	//		panic(err)
	//	}
	//}
	//if len(config.TLSCertContext) == 0 {
	//	config.TLSCertContext, err = ioutil.ReadFile(config.Cert)
	//	if err != nil {
	//		panic(err)
	//	}
	//}
	//var connections []struct {
	//	GroupID string
	//	NodeURL string
	//}
	////if viper.IsSet("Network.Connection.NodeURL") {
	//err := viper.UnmarshalKey("Network.Connection", &connections)
	//if err != nil {
	//	return nil, fmt.Errorf("parse Network.Connection failed. err: %v", err)
	//}
	//for i := range connections {
	//	configs = append(configs, *config)
	//	configs[i].GroupID = connections[i].GroupID
	//	configs[i].NodeURL = connections[i].NodeURL
	//}
	//} else {
	//	return nil, fmt.Errorf("Network.Connection has not been set")
	//}
	//} else {
	//	return nil, fmt.Errorf("network has not been set")
	//}
	return configs, nil
}

// ParseConfigOptions parses from arguments
func ParseConfigOptions(caFile string, key string, cert, keyFile string, groupId string, ipPort string, isHttp bool, chainId string, isSMCrypto bool) (*Config, error) {
	config := Config{
		IsHTTP:     isHttp,
		ChainID:    chainId,
		CAFile:     caFile,
		Key:        key,
		Cert:       cert,
		IsSMCrypto: isSMCrypto,
		GroupID:    groupId,
		NodeURL:    ipPort,
	}
	keyBytes, curve, err := LoadECPrivateKeyFromPEM(keyFile)
	if err != nil {
		return nil, fmt.Errorf("parse private key failed, err: %v", err)
	}
	if config.IsSMCrypto && curve != sm2p256v1 {
		return nil, fmt.Errorf("smcrypto must use sm2p256v1 private key, but found %s", curve)
	}
	if !config.IsSMCrypto && curve != secp256k1 {
		return nil, fmt.Errorf("must use secp256k1 private key, but found %s", curve)
	}
	config.PrivateKey = keyBytes
	return &config, nil
}
