// Copyright FISCO-BCOS go-sdk
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	tls "github.com/FISCO-BCOS/crypto/tls"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

const (
	maxTopicLength      = 254
	messageHeaderLength = 42
	protocolVersion     = 3
	clientType          = "Go-SDK"
)

type nodeInfo struct {
	blockNumber       int64
	Protocol          int32  `json:"protocol"`
	CompatibleVersion string `json:"nodeVersion"`
}

type channelSession struct {
	// groupID   uint
	c         *tls.Conn
	mu        sync.RWMutex
	responses map[string]*channelResponse
	// receiptsMutex sync.Mutex
	receiptResponses  map[string]*channelResponse
	topicMu           sync.RWMutex
	topicHandlers     map[string]func([]byte)
	topicAuthHandlers map[string]func([]byte)
	buf               []byte
	nodeInfo          nodeInfo
	closeOnce         sync.Once
	closed            chan interface{}
}

const (
	// channel messages types
	rpcMessage             = 0x12   // channel rpc request
	clientHeartbeat        = 0x13   // Heartbeat for sdk
	clientHandshake        = 0x14   // type for hand shake
	clientRegisterEventLog = 0x15   // type for event log filter register request and response
	amopPushRandom         = 0x30   // type for request from sdk
	amopResponse           = 0x31   // type for response to sdk
	amopSubscribeTopics    = 0x32   // type for topic request
	amopMultiCast          = 0x35   // type for mult broadcast
	amopAuthTopic          = 0x37   // type for verified topic
	amopUpdateTopicStatus  = 0x38   // type for update status
	transactionNotify      = 0x1000 // type for  transaction notify
	blockNotify            = 0x1001 // type for  block notify
	eventLogPush           = 0x1002 // type for event log push

	// AMOP error code
	success                            = 0
	remotePeerUnavailable              = 100
	remoteClientPeerUnavailable        = 101
	timeout                            = 102
	rejectAmopReqForOverBandwidthLimit = 103
	sendChannelMessageFailed           = 104

	// authTopic prefix
	normalTopicPrefix     = "#!$TopicNeedVerify_"
	publisherTopicPrefix  = "#!$PushChannel_#!$TopicNeedVerify_"
	subscriberTopicPrefix = "#!$VerifyChannel_#!$TopicNeedVerify_"
)

type topicData struct {
	length uint8
	topic  string
	data   []byte
}

type channelMessage struct {
	length    uint32
	typeN     uint16
	uuid      string
	errorCode int32
	body      []byte
}

type handshakeRequest struct {
	MinimumSupport int32  `json:"minimumSupport"`
	MaximumSupport int32  `json:"maximumSupport"`
	ClientType     string `json:"clientType"`
}

type handshakeResponse struct {
	Protocol    int32  `json:"protocol"`
	NodeVersion string `json:"nodeVersion"`
}

type channelResponse struct {
	Message *channelMessage
	Notify  chan interface{}
}

type nodeRequestSdkVerifyTopic struct {
	Topic        string
	TopicForCert string
	NodeId       string
}

type sdkRequestNodeUpdateTopicStatus struct {
	CheckResult int    `json:"checkResult"`
	NodeId      string `json:"nodeId"`
	Topic       string `json:"topic"`
}

func newChannelMessage(msgType uint16, body []byte) (*channelMessage, error) {
	id, err := uuid.NewUUID()
	if err != nil {
		log.Fatal("newChannelMessage error:", err)
		return nil, err
	}
	idString := strings.ReplaceAll(id.String(), "-", "")
	// var idByte [32]byte
	// copy(idByte[:], idString[:32])
	msg := &channelMessage{length: uint32(messageHeaderLength + len(body)), typeN: msgType,
		errorCode: 0, uuid: idString, body: body}
	return msg, nil
}

func newTopicMessage(t string, data []byte, msgType uint16) (*channelMessage, error) {
	if len(t) > maxTopicLength {
		return nil, fmt.Errorf("topic length exceeds 254")
	}
	topic := &topicData{length: uint8(len(t)) + 1, topic: t, data: data}
	mesgData := topic.Encode()
	return newChannelMessage(msgType, mesgData)
}

func (t *topicData) Encode() []byte {
	var raw []byte
	buf := bytes.NewBuffer(raw)
	err := binary.Write(buf, binary.LittleEndian, t.length)
	if err != nil {
		log.Fatal("encode length error:", err)
	}
	err = binary.Write(buf, binary.LittleEndian, []byte(t.topic))
	if err != nil {
		log.Fatal("encode type error:", err)
	}
	err = binary.Write(buf, binary.LittleEndian, t.data)
	if err != nil {
		log.Fatal("encode uuid error:", err)
	}
	return buf.Bytes()
}

func (msg *channelMessage) Encode() []byte {
	var raw []byte
	buf := bytes.NewBuffer(raw)
	err := binary.Write(buf, binary.BigEndian, msg.length)
	if err != nil {
		log.Fatal("encode length error:", err)
	}
	err = binary.Write(buf, binary.BigEndian, msg.typeN)
	if err != nil {
		log.Fatal("encode type error:", err)
	}
	err = binary.Write(buf, binary.LittleEndian, []byte(msg.uuid))
	if err != nil {
		log.Fatal("encode uuid error:", err)
	}
	err = binary.Write(buf, binary.BigEndian, msg.errorCode)
	if err != nil {
		log.Fatal("encode ErrorCode error:", err)
	}
	err = binary.Write(buf, binary.LittleEndian, msg.body)
	if err != nil {
		log.Fatal("encode Body error:", err)
	}
	if uint32(buf.Len()) != msg.length {
		fmt.Printf("%d != %d\n, buf is %v", buf.Len(), msg.length, buf.String())
		log.Fatal("encode error length error:", err)
	}
	return buf.Bytes()
}

func decodeChannelMessage(raw []byte) (*channelMessage, error) {
	buf := bytes.NewReader(raw)
	result := new(channelMessage)
	err := binary.Read(buf, binary.BigEndian, &result.length)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	if uint32(len(raw)) < result.length {
		return nil, errors.New("uncomplete message")
	}
	err = binary.Read(buf, binary.BigEndian, &result.typeN)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	var uuid [32]byte
	err = binary.Read(buf, binary.LittleEndian, &uuid)
	if err != nil {
		// log.Fatal("encode error:", err)
		fmt.Println("binary.Read failed:", err)
	}
	result.uuid = string(uuid[:])

	err = binary.Read(buf, binary.BigEndian, &result.errorCode)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	dataLength := result.length - messageHeaderLength
	result.body = make([]byte, dataLength, dataLength)
	err = binary.Read(buf, binary.BigEndian, &result.body)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	return result, nil
}

func decodeTopic(raw []byte) (*topicData, error) {
	buf := bytes.NewReader(raw)
	result := new(topicData)
	err := binary.Read(buf, binary.LittleEndian, &result.length)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	topic := make([]byte, result.length-1, result.length-1)
	err = binary.Read(buf, binary.LittleEndian, &topic)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	result.topic = string(topic)
	dataLength := len(raw) - int(result.length)
	result.data = make([]byte, dataLength, dataLength)
	err = binary.Read(buf, binary.LittleEndian, &result.data)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
	}
	return result, nil
}

// channelCon n is treated specially by Connection.
func (hc *channelSession) Write(context.Context, interface{}) error {
	panic("Write called on channelSession")
}

func (hc *channelSession) RemoteAddr() string {
	return hc.c.RemoteAddr().String()
}

func (hc *channelSession) Read() ([]*jsonrpcMessage, bool, error) {
	<-hc.closed
	return nil, false, io.EOF
}

func (hc *channelSession) Close() {
	hc.closeOnce.Do(func() { close(hc.closed) })
}

func (hc *channelSession) Closed() <-chan interface{} {
	return hc.closed
}

// ChannelTimeouts represents the configuration params for the Channel RPC subscriber.
type ChannelTimeouts struct {
	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body.
	//
	// Because ReadTimeout does not let Handlers make per-request
	// decisions on each request body's acceptable deadline or
	// upload rate, most users will prefer to use
	// ReadHeaderTimeout. It is valid to use them both.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. It is reset whenever a new
	// request's header is read. Like ReadTimeout, it does not
	// let Handlers make decisions on a per-request basis.
	WriteTimeout time.Duration

	// IdleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled. If IdleTimeout
	// is zero, the value of ReadTimeout is used. If both are
	// zero, ReadHeaderTimeout is used.
	IdleTimeout time.Duration
}

// DefaultChannelTimeouts represents the default timeout values used if further
// configuration is not provided.
var DefaultChannelTimeouts = ChannelTimeouts{
	ReadTimeout:  30 * time.Second,
	WriteTimeout: 30 * time.Second,
	IdleTimeout:  120 * time.Second,
}

// DialChannelWithClient creates a new RPC client that connects to an RPC subscriber over Channel
// using the provided Channel Client.
func DialChannelWithClient(endpoint string, config *tls.Config, groupID int) (*Connection, error) {
	initctx := context.Background()
	return newClient(initctx, func(context.Context) (ServerCodec, error) {
		conn, err := tls.Dial("tcp", endpoint, config)
		if err != nil {
			return nil, err
		}
		ch := &channelSession{c: conn, responses: make(map[string]*channelResponse),
			receiptResponses: make(map[string]*channelResponse), topicHandlers: make(map[string]func([]byte)),
			topicAuthHandlers: make(map[string]func([]byte)),
			nodeInfo:          nodeInfo{blockNumber: 0, Protocol: 1}, closed: make(chan interface{})}
		go ch.processMessages()
		if err = ch.handshakeChannel(); err != nil {
			fmt.Printf("handshake channel protocol failed, use default protocol version")
		}
		if err = ch.subscribeTopic("_block_notify_"+strconv.Itoa(groupID), func(i []byte) {}); err != nil {
			return nil, fmt.Errorf("subscriber block nofity failed")
		}
		return ch, nil
	})
}

func (c *Connection) sendRPCRequest(ctx context.Context, op *requestOp, msg interface{}) error {
	hc := c.writeConn.(*channelSession)
	rpcMsg := msg.(*jsonrpcMessage)
	if rpcMsg.Method == "sendRawTransaction" {
		respBody, err := hc.sendTransaction(ctx, msg)
		if err != nil {
			return fmt.Errorf("sendTransaction failed, %v", err)
		}
		rpcResp := new(jsonrpcMessage)
		rpcResp.Result = respBody
		op.resp <- rpcResp
	} else {
		respBody, err := hc.doRPCRequest(ctx, msg)
		if respBody != nil {
			defer respBody.Close()
		}

		if err != nil {
			if respBody != nil {
				buf := new(bytes.Buffer)
				if _, err2 := buf.ReadFrom(respBody); err2 == nil {
					return fmt.Errorf("%v %v", err, buf.String())
				}
			}
			return err
		}
		var respmsg jsonrpcMessage
		if err := json.NewDecoder(respBody).Decode(&respmsg); err != nil {
			return err
		}
		op.resp <- &respmsg
	}
	return nil
}

func (c *Connection) sendBatchChannel(ctx context.Context, op *requestOp, msgs []*jsonrpcMessage) error {
	hc := c.writeConn.(*channelSession)
	respBody, err := hc.doRPCRequest(ctx, msgs)
	if err != nil {
		return err
	}
	defer respBody.Close()
	var respmsgs []jsonrpcMessage
	if err := json.NewDecoder(respBody).Decode(&respmsgs); err != nil {
		return err
	}
	for i := 0; i < len(respmsgs); i++ {
		op.resp <- &respmsgs[i]
	}
	return nil
}

func (hc *channelSession) doRPCRequest(ctx context.Context, msg interface{}) (io.ReadCloser, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	var rpcMsg *channelMessage
	rpcMsg, err = newChannelMessage(rpcMessage, body)
	if err != nil {
		return nil, err
	}
	msgBytes := rpcMsg.Encode()

	_, err = hc.c.Write(msgBytes)
	if err != nil {
		return nil, err
	}
	response := &channelResponse{Message: nil, Notify: make(chan interface{})}
	hc.mu.Lock()
	hc.responses[rpcMsg.uuid] = response
	hc.mu.Unlock()

	<-response.Notify
	hc.mu.Lock()
	response = hc.responses[rpcMsg.uuid]
	delete(hc.responses, rpcMsg.uuid)
	hc.mu.Unlock()
	if response.Message.errorCode != 0 {
		return nil, errors.New("response error:" + string(response.Message.errorCode))
	}
	return ioutil.NopCloser(bytes.NewReader(response.Message.body)), nil
}

func (hc *channelSession) sendTransaction(ctx context.Context, msg interface{}) ([]byte, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	var rpcMsg *channelMessage
	rpcMsg, err = newChannelMessage(rpcMessage, body)
	if err != nil {
		return nil, err
	}

	response := &channelResponse{Message: nil, Notify: make(chan interface{})}
	receiptResponse := &channelResponse{Message: nil, Notify: make(chan interface{})}
	hc.mu.Lock()
	hc.responses[rpcMsg.uuid] = response
	hc.receiptResponses[rpcMsg.uuid] = receiptResponse
	hc.mu.Unlock()
	defer func() {
		hc.mu.Lock()
		delete(hc.responses, rpcMsg.uuid)
		delete(hc.receiptResponses, rpcMsg.uuid)
		hc.mu.Unlock()
	}()
	msgBytes := rpcMsg.Encode()
	_, err = hc.c.Write(msgBytes)
	if err != nil {
		return nil, err
	}
	<-response.Notify

	hc.mu.Lock()
	response = hc.responses[rpcMsg.uuid]
	delete(hc.responses, rpcMsg.uuid)
	hc.mu.Unlock()
	if response.Message.errorCode != 0 {
		return nil, errors.New("response error:" + string(response.Message.errorCode))
	}
	var respmsg jsonrpcMessage
	if err := json.NewDecoder(bytes.NewReader(response.Message.body)).Decode(&respmsg); err != nil {
		return nil, err
	}
	if respmsg.Error != nil {
		return nil, fmt.Errorf("send transaction error, code=%d, message=%s", respmsg.Error.Code, respmsg.Error.Message)
	}
	// fmt.Printf("sendTransaction reveived response,seq:%s message:%s\n ", rpcMsg.uuid, respmsg.Result)

	<-receiptResponse.Notify

	hc.mu.RLock()
	receiptResponse = hc.receiptResponses[rpcMsg.uuid]
	hc.mu.RUnlock()
	if receiptResponse.Message.errorCode != 0 {
		return nil, errors.New("response error:" + string(receiptResponse.Message.errorCode))
	}
	return receiptResponse.Message.body, nil
}

func (hc *channelSession) sendMessageNoResponse(msg *channelMessage) error {
	msgBytes := msg.Encode()
	_, err := hc.c.Write(msgBytes)
	if err != nil {
		return err
	}
	return nil
}

func (hc *channelSession) sendMessage(msg *channelMessage) (*channelMessage, error) {
	msgBytes := msg.Encode()
	response := &channelResponse{Message: nil, Notify: make(chan interface{})}
	hc.mu.Lock()
	hc.responses[msg.uuid] = response
	hc.mu.Unlock()
	_, err := hc.c.Write(msgBytes)
	if err != nil {
		return nil, err
	}
	defer func() {
		hc.mu.Lock()
		delete(hc.responses, msg.uuid)
		hc.mu.Unlock()
	}()
	fmt.Println("qiubing 999999999999999999999999999999999999999999999")
	fmt.Println("qiubing msg.uuid   " + msg.uuid)
	<-response.Notify
	fmt.Println("qiubing 888888888888888888888888888888888888888888888")
	fmt.Printf("qiubing amop: %v", msg.body)
	hc.mu.Lock()
	response = hc.responses[msg.uuid]
	hc.mu.Unlock()
	switch response.Message.errorCode {
	case success:
		_ = struct{}{}
	case remotePeerUnavailable:
		return nil, fmt.Errorf("error code %v, remote peer unavailable", remotePeerUnavailable)
	case remoteClientPeerUnavailable:
		return nil, fmt.Errorf("error code %v, remote client peer unavailable", remoteClientPeerUnavailable)
	case timeout:
		return nil, fmt.Errorf("error code %v, timeout", timeout)
	case rejectAmopReqForOverBandwidthLimit:
		return nil, fmt.Errorf("error code %v, reject amop reqeust or over bandwidth limit", rejectAmopReqForOverBandwidthLimit)
	case sendChannelMessageFailed:
		return nil, fmt.Errorf("error code %v, send channel message failed", sendChannelMessageFailed)
	default:
		return nil, fmt.Errorf("response error: %v", response.Message.errorCode)
	}
	return response.Message, nil
}

func (hc *channelSession) handshakeChannel() error {
	handshakeBody := handshakeRequest{MinimumSupport: 1, MaximumSupport: protocolVersion, ClientType: clientType}
	body, err := json.Marshal(handshakeBody)
	if err != nil {
		return fmt.Errorf("encode handshake request failed %w", err)
	}
	var msg, response *channelMessage
	msg, err = newChannelMessage(clientHandshake, body)
	if err != nil {
		return err
	}
	response, err = hc.sendMessage(msg)
	if err != nil {
		return err
	}
	var info nodeInfo
	if err = json.Unmarshal(response.body, &info); err != nil {
		return fmt.Errorf("parse handshake channel protocol response failed %w", err)
	}
	hc.nodeInfo = info
	// fmt.Printf("node info:%+v", info)
	return nil
}

func (hc *channelSession) subscribeTopic(topic string, handler func([]byte)) error {
	if len(topic) > maxTopicLength {
		return errors.New("topic length exceeds 254")
	}
	if handler == nil {
		return errors.New("handler is nil")
	}
	if _, ok := hc.topicHandlers[topic]; ok {
		return errors.New("already subscribed to topic " + topic)
	}
	if _, ok := hc.topicAuthHandlers[topic]; ok {
		return errors.New("already subscribed to topic " + topic)
	}
	hc.topicMu.Lock()
	hc.topicHandlers[topic] = handler
	hc.topicMu.Unlock()

	keys := make([]string, 0, len(hc.topicHandlers))
	for k := range hc.topicHandlers {
		keys = append(keys, k)
	}
	data, err := json.Marshal(keys)
	if err != nil {
		hc.topicMu.Lock()
		delete(hc.topicHandlers, topic)
		hc.topicMu.Unlock()
		return errors.New("marshal topics failed")
	}
	msg, err := newChannelMessage(amopSubscribeTopics, data)
	if err != nil {
		return fmt.Errorf("newChannelMessage failed, err: %v", err)
	}
	return hc.sendMessageNoResponse(msg)
}

func (hc *channelSession) subscribeAuthTopic(topic string, privateKey *ecdsa.PrivateKey, handler func([]byte)) error {
	if len(topic) > maxTopicLength {
		return errors.New("topic length exceeds 254")
	}
	if handler == nil {
		return errors.New("handler is nil")
	}
	if _, ok := hc.topicHandlers[topic]; ok {
		return errors.New("already subscribed to topic " + topic)
	}
	if _, ok := hc.topicAuthHandlers[topic]; ok {
		return errors.New("already subscribed to topic " + topic)
	}
	hc.topicMu.Lock()
	hc.topicAuthHandlers[topic] = handler
	hc.topicAuthHandlers[normalTopicPrefix+topic] = handler
	hc.topicAuthHandlers[subscriberTopicPrefix+topic] = func(data []byte) {
		object := struct {
			Data []byte
			UUID string
		}{}
		err := json.Unmarshal(data, &object)
		if err != nil {
			log.Printf("unmarshal object failed, err: %v", err)
			return
		}
		randomNumStr := string(object.Data)
		randomNum, err := strconv.Atoi(randomNumStr)
		if err != nil {
			log.Printf("string to int failed, err: %v", err)
		}
		signature, err := signForRandomNum(randomNum, privateKey)
		if err != nil {
			log.Printf("sign for random number failed, err: %v", err)
		}
		//responseMessage, err := newTopicMessage(publisherTopicPrefix+topic, signature, amopResponse)
		//responseMessage, err := newTopicMessage(topic, signature, amopResponse)
		responseMessage, err := newTopicMessage(subscriberTopicPrefix+topic, signature, amopResponse)
		if err != nil {
			log.Printf("%v", err)
		}
		responseMessage.uuid = object.UUID
		err = hc.sendMessageNoResponse(responseMessage)
		fmt.Printf("qiubing                   responseMessage   %+v", responseMessage)
		if err != nil {
			log.Printf("response message failed")
		}
	}
	hc.topicMu.Unlock()

	keys := make([]string, 0, len(hc.topicHandlers)+len(hc.topicAuthHandlers))
	for k := range hc.topicHandlers {
		keys = append(keys, k)
	}
	for k := range hc.topicAuthHandlers {
		keys = append(keys, k)
	}
	data, err := json.Marshal(keys)
	if err != nil {
		hc.topicMu.Lock()
		delete(hc.topicAuthHandlers, topic)
		hc.topicMu.Unlock()
		return errors.New("marshal topics failed")
	}
	msg, err := newChannelMessage(amopSubscribeTopics, data)
	if err != nil {
		return fmt.Errorf("newChannelMessage failed, err: %v", err)
	}
	fmt.Println("qiubing 333333333333333333333333333333333333333333333")
	return hc.sendMessageNoResponse(msg)
}

func (hc *channelSession) publishAuthTopic(topic string, publicKeys []*ecdsa.PublicKey, handler func([]byte)) error {
	if len(topic) > maxTopicLength {
		return errors.New("topic length exceeds 254")
	}
	if handler == nil {
		return errors.New("handler is nil")
	}
	if _, ok := hc.topicHandlers[topic]; ok {
		return errors.New("already subscribed to topic " + topic)
	}
	if _, ok := hc.topicAuthHandlers[topic]; ok {
		return errors.New("already subscribed to topic " + topic)
	}
	hc.topicMu.Lock()
	hc.topicAuthHandlers[topic] = handler
	hc.topicAuthHandlers[normalTopicPrefix+topic] = handler
	hc.topicAuthHandlers[publisherTopicPrefix+topic] = func(data []byte) {
		nodeID := string(data)
		randomNum := generateRandomNum()
		msg, err := newTopicMessage(subscriberTopicPrefix+topic, []byte(strconv.Itoa(randomNum)), amopPushRandom)
		if err != nil {
			log.Fatalf("new topic message failed, err: %v", err)
		}
		fmt.Println("qiubing 22222222222222222222222222222222222222222222")
		response, err := hc.sendMessage(msg)
		if err != nil {
			log.Fatalf("send message failed, err: %v", err)
		}
		signature := response.body
		var checkResult int
		if verifyRandomNumSigned(signature, publicKeys, generateDigestHash(randomNum)) {
			checkResult = 0
		} else {
			checkResult = 1
		}
		var nodeUpdateTopicStatus = new(sdkRequestNodeUpdateTopicStatus)
		nodeUpdateTopicStatus.CheckResult = checkResult
		nodeUpdateTopicStatus.Topic = topic
		nodeUpdateTopicStatus.NodeId = nodeID
		jsonBytes, err := json.Marshal(nodeUpdateTopicStatus)
		if err != nil {
			log.Printf("nodeUpdateTopicStatus marshal failed, err: %v", err)
		}
		newMessage, err := newTopicMessage(topic, jsonBytes, amopUpdateTopicStatus)
		if err != nil {
			log.Fatalf("new topic message failed, err: %v", err)
		}
		err = hc.sendMessageNoResponse(newMessage)
		if err != nil {
			log.Fatalf("send message no response failed, err: %v", err)
		}
	}
	hc.topicMu.Unlock()

	keys := make([]string, 0, len(hc.topicHandlers)+len(hc.topicAuthHandlers))
	for k := range hc.topicHandlers {
		keys = append(keys, k)
	}
	for k := range hc.topicAuthHandlers {
		keys = append(keys, k)
	}
	data, err := json.Marshal(keys)
	if err != nil {
		hc.topicMu.Lock()
		delete(hc.topicAuthHandlers, topic)
		hc.topicMu.Unlock()
		return errors.New("marshal topics failed")
	}
	msg, err := newChannelMessage(amopSubscribeTopics, data)
	if err != nil {
		return fmt.Errorf("newChannelMessage failed, err: %v", err)
	}
	fmt.Println("qiubing 111111111111111111111111111111111111111")
	return hc.sendMessageNoResponse(msg)
}

func (hc *channelSession) unsubscribeAuthTopic(topic string) error {
	if _, ok := hc.topicAuthHandlers[topic]; !ok {
		return fmt.Errorf("topic \"%v\" has't been subscribed", topic)
	}
	hc.topicMu.Lock()
	delete(hc.topicAuthHandlers, topic)
	delete(hc.topicAuthHandlers, normalTopicPrefix+topic)
	delete(hc.topicAuthHandlers, publisherTopicPrefix+topic)
	delete(hc.topicAuthHandlers, subscriberTopicPrefix+topic)
	hc.topicMu.Unlock()

	keys := make([]string, 0, len(hc.topicAuthHandlers)+len(hc.topicHandlers))
	for k := range hc.topicHandlers {
		keys = append(keys, k)
	}
	for k := range hc.topicAuthHandlers {
		keys = append(keys, k)
	}
	return hc.updateSubscribeTopic(keys)
}

func (hc *channelSession) unsubscribeTopic(topic string) error {
	if _, ok := hc.topicHandlers[topic]; !ok {
		return fmt.Errorf("topic \"%v\" has't been subscribed", topic)
	}
	hc.topicMu.Lock()
	delete(hc.topicHandlers, topic)
	hc.topicMu.Unlock()

	keys := make([]string, 0, len(hc.topicHandlers)+len(hc.topicAuthHandlers))
	for k := range hc.topicHandlers {
		keys = append(keys, k)
	}
	for k := range hc.topicAuthHandlers {
		keys = append(keys, k)
	}
	return hc.updateSubscribeTopic(keys)
}

func (hc *channelSession) updateSubscribeTopic(topics []string) error {
	data, err := json.Marshal(topics)
	if err != nil {
		return errors.New("marshal topics failed")
	}
	msg, err := newChannelMessage(amopSubscribeTopics, data)
	if err != nil {
		return fmt.Errorf("newChannelMessage failed, err: %v", err)
	}
	return hc.sendMessageNoResponse(msg)
}

func (hc *channelSession) pushTopicDataRandom(topic string, data []byte) error {
	msg, err := newTopicMessage(topic, data, amopPushRandom)
	if err != nil {
		return fmt.Errorf("new topic message failed, err: %v", err)
	}
	message, err := hc.sendMessage(msg)
	if err != nil {
		return fmt.Errorf("sendMessage failed, err: %v", err)
	}
	object, err := decodeTopic(message.body)
	fmt.Printf("qiubing decodeTopic: %+v\n", object)
	fmt.Printf("qiubing decodeTopic: %v\n", string(object.data))
	return nil
}

func (hc *channelSession) pushTopicDataToALL(topic string, data []byte) error {
	msg, err := newTopicMessage(topic, data, amopMultiCast)
	if err != nil {
		return err
	}
	message, err := hc.sendMessage(msg)
	if err != nil {
		return fmt.Errorf("pushTopicDataToALL, sendMessage failed, err: %v", err)
	}
	_, err = decodeTopic(message.body)
	if err != nil {
		return fmt.Errorf("pushTopicDataToALL, decodeTopic failed, err: %v", err)
	}
	return nil
}

func (hc *channelSession) processTopicMessage(msg *channelMessage) error {
	fmt.Println("qiubing       msg.body" + string(msg.body))
	topic, err := decodeTopic(msg.body)
	if err != nil {
		fmt.Printf("decode topic failed: %+v", msg)
		return err
	}
	hc.topicMu.RLock()
	handler, ok := hc.topicAuthHandlers[topic.topic]
	hc.topicMu.RUnlock()
	if ok && strings.Contains(topic.topic, subscriberTopicPrefix) {
		fmt.Println("qiubing        77777777777777777777777777777777777777777777777777")
		fmt.Println("qiubing    topic.data   " + string(topic.data))
		fmt.Println("qiubing    msg.uuid  " + msg.uuid)
		jsonStruct := struct {
			Data []byte
			UUID string
		}{
			topic.data,
			msg.uuid,
		}
		jsonBytes, err := json.Marshal(jsonStruct)
		if err != nil {
			fmt.Errorf("json marshal failed, err: %v", jsonBytes)
		}
		handler(jsonBytes)
		return nil
	}
	if !ok {
		hc.topicMu.RLock()
		handler, ok = hc.topicHandlers[topic.topic]
		hc.topicMu.RUnlock()
		if !ok {
			return fmt.Errorf("unsubscribe topic %s", topic.topic)
		}
	}
	responseMessage, err := newTopicMessage(topic.topic, []byte("test amop"), amopResponse)
	if err != nil {
		return err
	}
	responseMessage.uuid = msg.uuid
	err = hc.sendMessageNoResponse(responseMessage)
	if err != nil {
		return fmt.Errorf("response message failed")
	}
	handler(topic.data)
	return nil
}

func (hc *channelSession) processAuthTopicMessage(msg *channelMessage) error {
	authInfo := new(nodeRequestSdkVerifyTopic)
	err := json.Unmarshal(msg.body, authInfo)
	if err != nil {
		fmt.Printf("unmarshal msg.body failed, err: %v", err)
		return err
	}
	strArr := strings.Split(authInfo.Topic, "#!$TopicNeedVerify_")
	if len(strArr) == 0 {
		return errors.New("topic is not existed")
	}
	var topic = strArr[len(strArr)-1]
	fmt.Println("qiubing topic   " + topic)
	hc.topicMu.RLock()
	handler, ok := hc.topicAuthHandlers[publisherTopicPrefix+topic]
	hc.topicMu.RUnlock()
	if !ok {
		return fmt.Errorf("topic %s is not existed", topic)
	}
	handler([]byte(authInfo.NodeId))
	return nil
}

func (hc *channelSession) processMessages() {
	for {
		select {
		case <-hc.closed:
			return
		default:
			receiveBuf := make([]byte, 4096)
			b, err := hc.c.Read(receiveBuf)
			if err != nil {
				// fmt.Printf("channel Read error:%v", err)
				hc.Close()
				continue
			}
			hc.buf = append(hc.buf, receiveBuf[:b]...)
			msg, err := decodeChannelMessage(hc.buf)
			if err != nil {
				// fmt.Printf("decodeChannelMessage error:%v", err)
				continue
			}
			// fmt.Printf("message %+v\n", msg)
			hc.buf = hc.buf[msg.length:]
			hc.mu.Lock()
			if response, ok := hc.responses[msg.uuid]; ok {
				fmt.Println("qiubing       80808080808080808080808080808080808080808080")
				response.Message = msg
				response.Notify <- struct{}{}
			}
			hc.mu.Unlock()
			switch msg.typeN {
			case amopResponse, rpcMessage, clientHandshake:
				fmt.Println("qiubing 1010101101010101101010110101010")
				// fmt.Printf("response type:%d seq:%s, msg:%s", msg.typeN, msg.uuid, string(msg.body))
			case transactionNotify:
				// fmt.Printf("transaction notify:%s", string(msg.body))
				hc.mu.Lock()
				if receipt, ok := hc.receiptResponses[msg.uuid]; ok {
					receipt.Message = msg
					receipt.Notify <- struct{}{}
				} else {
					fmt.Printf("error %+v", receipt)
				}
				hc.mu.Unlock()
			case blockNotify:
				hc.updateBlockNumber(msg)
			case amopPushRandom, amopMultiCast:
				err := hc.processTopicMessage(msg)
				if err != nil {
					continue
				}
			case amopAuthTopic:
				fmt.Println("qiubing 5555555555555555555555555555555555555555")
				fmt.Printf("qiubing msg %+v", msg)
				err := hc.processAuthTopicMessage(msg)
				if err != nil {
					continue
				}
				// fmt.Printf("response type:%d seq:%s, msg:%s, err:%v", msg.typeN, msg.uuid, string(msg.body), err)
			default:
				fmt.Printf("unknown message type:%d, msg:%+v", msg.typeN, msg)
			}
		}
	}
}

func (hc *channelSession) updateBlockNumber(msg *channelMessage) {
	var blockNumber int64
	topic, err := decodeTopic(msg.body)
	if hc.nodeInfo.Protocol == 1 {
		response := strings.Split(string(topic.data), ",")
		blockNumber, err = strconv.ParseInt(response[1], 10, 32)
		if err != nil {
			fmt.Print("v1 block notify parse blockNumber failed")
			return
		}
	} else {
		var notify struct {
			GroupID     uint  `json:"groupID"`
			BlockNumber int64 `json:"blockNumber"`
		}
		err = json.Unmarshal(topic.data, &notify)
		if err != nil {
			fmt.Print("block notify parse blockNumber failed")
			return
		}
		blockNumber = notify.BlockNumber
	}
	// fmt.Printf("blockNumber updated %d -> %d", hc.nodeInfo.blockNumber, blockNumber)
	hc.nodeInfo.blockNumber = blockNumber
}

// channelServerConn turns a Channel connection into a Conn.
type channelServerConn struct {
	io.Reader
	io.Writer
	r *http.Request
}

func newChannelServerConn(r *http.Request, w http.ResponseWriter) ServerCodec {
	body := io.LimitReader(r.Body, maxRequestContentLength)
	conn := &channelServerConn{Reader: body, Writer: w, r: r}
	return NewJSONCodec(conn)
}

// Close does nothing and always returns nil.
func (t *channelServerConn) Close() error { return nil }

// RemoteAddr returns the peer address of the underlying connection.
func (t *channelServerConn) RemoteAddr() string {
	return t.r.RemoteAddr
}

// SetWriteDeadline does nothing and always returns nil.
func (t *channelServerConn) SetWriteDeadline(time.Time) error { return nil }

func generateRandomNum() int {
	rand.Seed(time.Now().Unix())
	num := rand.Int31()
	return int(num)
}

func signForRandomNum(num int, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	signature, err := crypto.Sign(generateDigestHash(num), privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign random number failed, err: %v\n", err)

	}
	return signature, nil
}

func generateDigestHash(num int) []byte {
	digestHash := sha256.Sum256([]byte(strconv.Itoa(num)))
	return digestHash[:]
}

func verifyRandomNumSigned(sig []byte, publicKeys []*ecdsa.PublicKey, digestHash []byte) bool {
	for i := 0; i < len(publicKeys); i++ {
		publicKeyBytes := crypto.FromECDSAPub(publicKeys[0])
		if crypto.VerifySignature(publicKeyBytes, digestHash, sig[:len(sig)-1]) {
			return true
		}
	}
	return false
}
