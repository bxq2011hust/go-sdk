package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
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
		log.Fatalf("parse configuration failed, err: %v\n", err)
	}
	c, err = client.Dial(&configs[0])
	if err != nil {
		log.Fatalf("init client failed, err: %v\n", err)
	}
}

func main() {
	if len(os.Args) != 3 {
		log.Fatal("the number of arguments is not equal 2")
	}
	topic := os.Args[1]
	count, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatal("the second parameter is not a number")
	}

	fmt.Println("3s...")
	time.Sleep(1 * time.Second)
	fmt.Println("2s...")
	time.Sleep(1 * time.Second)
	fmt.Println("1s...")
	time.Sleep(1 * time.Second)

	fmt.Println("start test")
	fmt.Println("===================================================================")

	message := "hello, FISCO BCOS, I am multi broadcast client!"
	for i := 0; i < count; i++ {
		time.Sleep(3 * time.Second)
		err = c.PushTopicDataToALL(topic, []byte(message))
		if err != nil {
			log.Printf("PushTopicDataToALL failed, err: %v\n", err)
		}
	}
	fmt.Println("PushTopicDataToALL success")
}
