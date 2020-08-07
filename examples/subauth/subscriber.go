package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/FISCO-BCOS/go-sdk/client"
	"github.com/FISCO-BCOS/go-sdk/conf"
)

const (
	privateKey1 = "efb3ffad703efe078b869ab83ba967d1694b0b88292b59cb710bceca4d4a2a98"
	privateKey2 = "0fe5e3ce06d6d48ec806ea17d13ce3d80e74b85f23c32c38f2c8e4180f539a7e"
	privateKey3 = "13e3531ac291bcf5674acd1c8c7c77b725dc9bf56242b02ef76bf970190412aa"
)

func onPush(data []byte) {
	fmt.Println("\n\n" + string(data))
}

var (
	c *client.Client
)

func init() {
	configs, err := conf.ParseConfigFile("config.toml")
	if err != nil {
		log.Fatalf("parse configuration failed, err: %v\n", err)
	}
	c, err = client.Dial(&configs[0])
	if err != nil {
		log.Fatalf("init client failed, err: %v\n", err)
	}
}

func main() {
	//if len(os.Args) != 2 {
	//	log.Fatal("the number of arguments is not equal 1")
	//}
	//topic := os.Args[1]
	topic := "hello"

	privateKey, err := crypto.HexToECDSA(privateKey1)
	if err != nil {
		log.Fatalf("hex to ECDSA failed, err: %v", privateKey)
	}
	err = c.SubscribeAuthTopic(topic, privateKey, onPush)
	if err != nil {
		fmt.Printf("SubscribeAuthTopic failed, err: %v\n", err)
		return
	}
	fmt.Println("SubscribeAuthTopic success")

	killSignal := make(chan os.Signal, 1)
	signal.Notify(killSignal, os.Interrupt)
	<-killSignal
}
