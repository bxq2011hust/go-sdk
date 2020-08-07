package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/status-im/keycard-go/hexutils"

	"github.com/FISCO-BCOS/go-sdk/client"
	"github.com/FISCO-BCOS/go-sdk/conf"
)

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

func onPush(data []byte) {
	fmt.Println("\n\n" + string(data))
}

const (
	publicKey1 = "123d81768ba899aa10574573854c191065bb60a870b56a596fc20d0f730446b1d5216bfb8d4e56cea977ae07157a4f4866556ad3113ab4b5a400388dfbc2e959"
	publicKey2 = "19dece101df106ca4baf478f98911cdc525db5c6b58f2189af9f69ff314e9f0bcb816b41fb8bd49ae830dc1087bf51c71a21c3e3a332132262b5ecf0189817f4"
	publicKey3 = "8b38138ea887220289276ca700e162647af79b4c61f33aefcfdaa2c3b714b2983084e519273208e8646b7f840e91b9053952df28a3bce1a6bca0132c26a36694"
)

func main() {
	//if len(os.Args) != 3 {
	//	log.Fatal("the number of arguments is not equal 2")
	//}
	//topic := os.Args[1]
	//count, err := strconv.Atoi(os.Args[2])
	//if err != nil {
	//	log.Fatal("the second parameter is not a number")
	//}

	topic := "hello"
	//count := 5

	publicKeys := make([]*ecdsa.PublicKey, 0)
	pubKey1, err := crypto.UnmarshalPubkey(hexutils.HexToBytes("04" + publicKey1))
	pubKey2, err := crypto.UnmarshalPubkey(hexutils.HexToBytes("04" + publicKey2))
	pubKey3, err := crypto.UnmarshalPubkey(hexutils.HexToBytes("04" + publicKey3))
	if err != nil {
		log.Fatalf("decompress pubkey failed, err: %v", err)
	}
	publicKeys = append(publicKeys, pubKey1, pubKey2, pubKey3)
	err = c.PublishAuthTopic(topic, publicKeys, onPush)
	if err != nil {
		fmt.Printf("publish topic failed, err: %v\n", err)
		return
	}
	fmt.Println("publish topic success")

	//for i := 0; i < count; i++ {
	//	time.Sleep(3 * time.Second)
	//	message := "hello, FISCO BCOS, I am unicast client!"
	//	err = c.PushTopicDataRandom(topic, []byte(message))
	//	if err != nil {
	//		log.Fatalf("PushTopicDataRandom failed, err: %v\n", err)
	//	}
	//}

	killSignal := make(chan os.Signal, 1)
	signal.Notify(killSignal, os.Interrupt)
	<-killSignal
}
