package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/FISCO-BCOS/go-sdk/client"
	"github.com/FISCO-BCOS/go-sdk/conf"
)

var (
	c *client.Client
)

func init() {
	configs, err := conf.ParseConfigFile("config.toml")
	if err != nil {
		log.Fatalf("parse configuration failed, err: %v", err)
	}
	c, err = client.Dial(&configs[0])
	if err != nil {
		log.Fatalf("init client failed, err: %v\n", err)
	}
}

func onPush(data []byte) {
	fmt.Println("\n\n" + string(data))
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("the number of arguments is not equal 1")
	}
	topic := os.Args[1]

	fmt.Println("3s...")
	time.Sleep(1 * time.Second)
	fmt.Println("2s...")
	time.Sleep(1 * time.Second)
	fmt.Println("1s...")
	time.Sleep(1 * time.Second)

	fmt.Println("start test")
	fmt.Println("===================================================================")

	err := c.SubscribeTopic(topic, onPush)
	if err != nil {
		fmt.Printf("subscriber topic failed, err: %v\n", err)
		return
	}
	fmt.Println("subscriber success")

	killSignal := make(chan os.Signal, 1)
	signal.Notify(killSignal, os.Interrupt)
	<-killSignal
}
