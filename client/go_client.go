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

// Package client provides a client for the FISCO BCOS RPC API.
package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/FISCO-BCOS/bcos-c-sdk/bindings/go/csdk"
	"github.com/FISCO-BCOS/go-sdk/abi/bind"
	"github.com/FISCO-BCOS/go-sdk/core/types"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// Client defines typed wrappers for the Ethereum RPC API.
type Client struct {
	conn     *Connection
	groupID  string
	chainID  string
	auth     *bind.TransactOpts
	callOpts *bind.CallOpts
	smCrypto bool
}

const (
	V3_2_0     int   = 0x03020000
	indent           = "  "
	BlockLimit int64 = 600
)

// Dial connects a client to the given URL and groupID.
func Dial(configFile, groupID string, privateKey []byte) (*Client, error) {
	csdkPointer, err := newCSdkClientByConfigFile(configFile, groupID, privateKey)
	if err != nil {
		return nil, err
	}
	return newClient(csdkPointer)
}

// DialContext pass the context to the rpc client
func DialContext(ctx context.Context, config *Config) (*Client, error) {
	csdkPointer, err := newCSdkClient(config.GroupID, config.Host, config.Port, config.IsSMCrypto, config.PrivateKey, config.TLSCaFile, config.TLSKeyFile, config.TLSCertFile, config.TLSSmEnKeyFile, config.TLSSmEnCertFile)
	if err != nil {
		return nil, fmt.Errorf("new csdk failed: %v", err)
	}
	return newClient(csdkPointer)
}

func newCSdkClientByConfigFile(configFile, groupID string, privateKey []byte) (*csdk.CSDK, error) {
	return csdk.NewSDKByConfigFile(configFile, groupID, privateKey)
}

func newCSdkClient(groupID, host string, port int, isSmCrypto bool, privateKey []byte, tlsCaPath, tlsKeyPath, tlsCertPath, tlsSmEnKeyPath, tlsSEnCertPath string) (*csdk.CSDK, error) {
	path, _ := os.Getwd()
	if _, err := os.Stat(tlsCaPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("the file %s does not exist, current working directory is %s", tlsCaPath, path)
	} else if _, err := os.Stat(tlsCertPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("the file %s does not exist, current working directory is %s", tlsCertPath, path)
	} else if _, err := os.Stat(tlsKeyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("the file %s does not exist, current working directory is %s", tlsKeyPath, path)
	}
	if isSmCrypto {
		if _, err := os.Stat(tlsSmEnKeyPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("the file %s does not exist, current working directory is %s", tlsSmEnKeyPath, path)
		} else if _, err := os.Stat(tlsSEnCertPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("the file %s does not exist, current working directory is %s", tlsSEnCertPath, path)
		}
	}
	return csdk.NewSDK(groupID, host, port, isSmCrypto, privateKey, tlsCaPath, tlsKeyPath, tlsCertPath, tlsSmEnKeyPath, tlsSEnCertPath)
}

func newClient(csdkPointer *csdk.CSDK) (*Client, error) {
	c, err := NewClient(nil, csdkPointer)
	if err != nil {
		return nil, fmt.Errorf("new client errors failed: %v", err)
	}
	client := Client{conn: c, groupID: csdkPointer.GroupID(), chainID: csdkPointer.ChainID(), smCrypto: csdkPointer.SMCrypto()}
	if csdkPointer.SMCrypto() {
		client.auth = bind.NewSMCryptoTransactor(csdkPointer.PrivateKeyBytes())
	} else {
		privateKey, err := crypto.ToECDSA(csdkPointer.PrivateKeyBytes())
		if err != nil {
			return nil, fmt.Errorf("new client errors failed: %v", err)
		}
		client.auth.GasLimit = big.NewInt(30000000)
		client.callOpts = &bind.CallOpts{From: client.auth.From}
	}

	return &client, nil
}

// Close disconnects the rpc
func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) ReConn() {
	c.conn.ReConn()
}

// ============================================== FISCO BCOS Blockchain Access ================================================

func toCallArg(msg ethereum.CallMsg) interface{} {
	arg := map[string]interface{}{
		"from": msg.From.String(),
		"to":   strings.ToLower(msg.To.String()[2:]),
	}
	if len(msg.Data) > 0 {
		arg["data"] = hexutil.Bytes(msg.Data).String()
	}
	if msg.Value != nil {
		arg["value"] = (*hexutil.Big)(msg.Value).String()
	}

	if msg.Gas != 0 {
		arg["gas"] = hexutil.Uint64(msg.Gas)
	}
	if msg.GasPrice != nil {
		arg["gasPrice"] = (*hexutil.Big)(msg.GasPrice)
	}

	return arg
}

type callResult struct {
	CurrentBlockNumber int    `json:"currentBlockNumber"`
	Output             string `json:"output"`
	Status             int    `json:"status"`
}

// GetTransactOpts return *bind.TransactOpts
func (c *Client) GetTransactOpts() *bind.TransactOpts {
	return c.auth
}

// SetTransactOpts set auth
func (c *Client) SetTransactOpts(opts *bind.TransactOpts) {
	c.auth = opts
}

// SetCallOpts set call opts
func (c *Client) SetCallOpts(opts *bind.CallOpts) {
	c.callOpts = opts
}

// GetCallOpts return *bind.CallOpts
func (c *Client) GetCallOpts() *bind.CallOpts {
	return c.callOpts
}

// WaitMined is wrapper of bind.WaitMined
func (c *Client) WaitMined(tx *types.Transaction) (*types.Receipt, error) {
	return bind.WaitMined(context.Background(), c, tx)
}

// SMCrypto returns true if use sm crypto
func (c *Client) SMCrypto() bool {
	return c.smCrypto
}

// CodeAt returns the contract code of the given account.
// The block number can be nil, in which case the code is taken from the latest known block.
func (c *Client) CodeAt(ctx context.Context, address common.Address, blockNumber *big.Int) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getCode", c.groupID, address.Hex())
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// Filters
func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	return hexutil.EncodeBig(number)
}

func toFilterArg(q ethereum.FilterQuery) (interface{}, error) {
	arg := map[string]interface{}{
		"address": q.Addresses,
		"topics":  q.Topics,
	}
	if q.BlockHash != nil {
		arg["blockHash"] = *q.BlockHash
		if q.FromBlock != nil || q.ToBlock != nil {
			return nil, fmt.Errorf("cannot specify both BlockHash and FromBlock/ToBlock")
		}
	} else {
		if q.FromBlock == nil {
			arg["fromBlock"] = "0x0"
		} else {
			arg["fromBlock"] = toBlockNumArg(q.FromBlock)
		}
		arg["toBlock"] = toBlockNumArg(q.ToBlock)
	}
	return arg, nil
}

// PendingCodeAt returns the contract code of the given account in the pending state.
func (c *Client) PendingCodeAt(ctx context.Context, address common.Address) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getCode", c.groupID, address.Hex())
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// CallContract invoke the call method of rpc api
func (c *Client) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	var hexBytes hexutil.Bytes
	var cr *callResult
	err := c.conn.CallContext(ctx, &cr, "call", c.groupID, toCallArg(msg))
	if err != nil {
		return nil, err
	}
	if cr.Status != 0 {
		var errorMessage string
		if len(cr.Output) >= 138 {
			outputBytes, err := hex.DecodeString(cr.Output[2:])
			if err != nil {
				return nil, fmt.Errorf("call error of status %d, hex.DecodeString failed", cr.Status)
			}
			errorMessage = string(outputBytes[68:])
		}
		return nil, fmt.Errorf("call error of status %d, %v", cr.Status, errorMessage)
	}
	hexBytes = common.FromHex(cr.Output)
	return hexBytes, nil
}

// PendingCallContract executes a message call transaction using the EVM.
// The state seen by the contract call is the pending state.
func (c *Client) PendingCallContract(ctx context.Context, msg ethereum.CallMsg) ([]byte, error) {
	var hexBytes hexutil.Bytes
	var cr *callResult
	err := c.conn.CallContext(ctx, &cr, "call", c.groupID, toCallArg(msg))
	if err != nil {
		return nil, err
	}
	if cr.Status != 0 {
		var errorMessage string
		if len(cr.Output) >= 138 {
			outputBytes, err := hex.DecodeString(cr.Output[2:])
			if err != nil {
				return nil, fmt.Errorf("call error of status %d, hex.DecodeString failed", cr.Status)
			}
			errorMessage = string(outputBytes[68:])
		}
		return nil, fmt.Errorf("call error of status %d, %v", cr.Status, errorMessage)
	}
	hexBytes = common.FromHex(cr.Output)
	return hexBytes, nil
}

// SendTransaction injects a signed transaction into the pending pool for execution.
//
// If the transaction was a contract creation use the TransactionReceipt method to get the
// contract address after the transaction has been mined.
func (c *Client) SendTransaction(ctx context.Context, tx *types.Transaction, contract *common.Address, input []byte) (*types.Receipt, error) {
	var err error
	var anonymityReceipt = &struct {
		types.Receipt
	}{}
	if contract != nil {
		err = c.conn.CallContext(ctx, anonymityReceipt, "sendRawTransaction", c.groupID, hexutil.Encode(input), strings.ToLower(contract.String()))
	} else {
		err = c.conn.CallContext(ctx, anonymityReceipt, "sendRawTransaction", c.groupID, hexutil.Encode(input), "")
	}
	if err != nil {
		errorStr := fmt.Sprintf("%s", err)
		if strings.Contains(errorStr, "connection refused") {
			log.Println("connection refused err:", err)
			return nil, err
		}
		return nil, err
	}
	return &anonymityReceipt.Receipt, nil
}

// AsyncSendTransaction send transaction async
func (c *Client) AsyncSendTransaction(ctx context.Context, tx *types.Transaction, contract *common.Address, input []byte, handler func(*types.Receipt, error)) error {
	var err error
	var anonymityReceipt = &struct {
		types.Receipt
	}{}
	if contract != nil {
		err = c.conn.CallContext(ctx, anonymityReceipt, "sendRawTransaction", c.groupID, hexutil.Encode(input), strings.ToLower(contract.String()[2:]))
	} else {
		err = c.conn.CallContext(ctx, anonymityReceipt, "sendRawTransaction", c.groupID, hexutil.Encode(input), "")
	}
	if err != nil {
		return nil
	}
	var receipt *types.Receipt
	go func() {
		for {
			receipt, err = c.TransactionReceipt(ctx, common.HexToHash(anonymityReceipt.TransactionHash))
			if receipt != nil {
				handler(receipt, nil)
				return
			}
			if err != nil {
				errorStr := fmt.Sprintf("%s", err)
				if strings.Contains(errorStr, "connection refused") {
					handler(nil, errors.New("connection refused"))
					return
				}
			}
		}
	}()
	return nil
}

// TransactionReceipt returns the receipt of a transaction by transaction hash.
// Note that the receipt is not available for pending transactions.
func (c *Client) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	return c.GetTransactionReceipt(ctx, txHash, true)
}

// eventlog
func (c *Client) SubscribeEventLogs(ctx context.Context, eventLogParams types.EventLogParams, handler func(int, []types.Log)) (string, error) {
	sendData, err := json.Marshal(eventLogParams)
	if err != nil {
		return "", err
	}
	log.Println("SubscribeEventLogs data:", string(sendData))
	var raw string
	err = c.conn.CallHandlerContext(ctx, &raw, "subscribeEventLogs", "", sendData, handler)
	if err != nil {
		return "", err
	}
	return raw, nil
}

func (c *Client) UnSubscribeEventLogs(ctx context.Context, taskId string) error {
	var raw interface{}
	err := c.conn.CallHandlerContext(ctx, &raw, "unSubscribeEventLogs", "", []byte(taskId), nil)
	if err != nil {
		return err
	}
	return nil
}

// amop
func (c *Client) SubscribeTopic(ctx context.Context, topic string, handler func([]byte, *[]byte)) error {
	var raw interface{}
	err := c.conn.CallHandlerContext(ctx, &raw, "subscribeTopic", topic, nil, handler)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) SendAMOPMsg(ctx context.Context, topic string, data []byte) error {
	var raw interface{}
	err := c.conn.CallHandlerContext(ctx, &raw, "SendAMOPMsg", topic, data, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) BroadcastAMOPMsg(ctx context.Context, topic string, data []byte) error {
	var raw interface{}
	err := c.conn.CallHandlerContext(ctx, &raw, "broadcastAMOPMsg", topic, data, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) UnsubscribeTopic(ctx context.Context, topic string) error {
	var raw interface{}
	err := c.conn.CallHandlerContext(ctx, &raw, "unsubscribeTopic", topic, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) SubscribeBlockNumberNotify(ctx context.Context, handler func(int64)) error {
	var raw interface{}
	err := c.conn.CallHandlerContext(ctx, &raw, "subscribeBlockNumberNotify", "", nil, handler)
	if err != nil {
		return err
	}
	return nil
}

//func (c *Client) UnsubscribeBlockNumberNotify() error {
//	return nil
//}

// GetGroupID returns the groupID of the client
func (c *Client) GetGroupID() string {
	return c.groupID
	//return big.NewInt(int64())
}

// SetGroupID sets the groupID of the client
func (c *Client) SetGroupID(newID string) {
	c.groupID = newID
}

// GetClientVersion returns the version of FISCO BCOS running on the nodes.
func (c *Client) GetClientVersion(ctx context.Context) (*types.ClientVersion, error) {
	var clientVersion types.ClientVersion
	err := c.conn.CallContext(ctx, &clientVersion, "getClientVersion")
	if err != nil {
		return nil, err
	}
	return &clientVersion, err
}

// GetChainID returns the Chain ID of the FISCO BCOS running on the nodes.
func (c *Client) GetChainID(ctx context.Context) (string, error) {
	//convertor := new(big.Int)
	chainId := c.chainID
	return chainId, nil
}

// GetBlockNumber returns the latest block height(hex format) on a given groupID.
func (c *Client) GetBlockNumber(ctx context.Context) (int64, error) {
	var raw int64
	err := c.conn.CallContext(ctx, &raw, "getBlockNumber", c.groupID)
	if err != nil {
		return -1, err
	}
	log.Println("json unmarshal respmsg blockNum:", raw)
	return raw, err
}

// GetBlockLimit returns the blocklimit for current blocknumber
func (c *Client) GetBlockLimit(ctx context.Context) (*big.Int, error) {
	var blockLimit *big.Int
	defaultNumber := big.NewInt(BlockLimit)
	var raw int
	err := c.conn.CallContext(ctx, &raw, "getBlockNumber", c.groupID)
	if err != nil {
		return nil, err
	}

	blockLimit = defaultNumber.Add(defaultNumber, big.NewInt(int64(raw)))
	return blockLimit, nil
}

// GetPBFTView returns the latest PBFT view(hex format) of the specific group and it will returns a wrong sentence
// if the consensus algorithm is not the PBFT.
func (c *Client) GetPBFTView(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getPbftView", c.groupID)
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
	// TODO
	// Raft consensus
}

// GetSealerList returns the list of consensus nodes' ID according to the groupID
func (c *Client) GetSealerList(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getSealerList", c.groupID)
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetObserverList returns the list of observer nodes' ID according to the groupID
func (c *Client) GetObserverList(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getObserverList", c.groupID)
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetConsensusStatus returns the status information about the consensus algorithm on a specific groupID
func (c *Client) GetConsensusStatus(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getConsensusStatus", c.groupID)
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetSyncStatus returns the synchronization status of the group
func (c *Client) GetSyncStatus(ctx context.Context) (*types.SyncStatus, error) {
	var syncStatus types.SyncStatus
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getSyncStatus", c.groupID)
	if err != nil {
		return nil, err
	}
	js := strings.Replace(raw.(string), "\\", "", -1)
	json.Unmarshal([]byte(js), &syncStatus)
	return &syncStatus, err
}

// GetPeers returns the information of the connected peers
func (c *Client) GetPeers(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getPeers", c.groupID)
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetGroupPeers returns the nodes and the overser nodes list on a specific group
func (c *Client) GetGroupPeers(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getGroupPeers", c.groupID)
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetNodeIDList returns the ID information of the connected peers and itself
func (c *Client) GetNodeIDList(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getNodeIDList", c.groupID)
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err

}

// GetGroupInfoList returns the ID information of the connected peers and itself
func (c *Client) GetGroupInfoList(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getGroupInfoList", c.groupID)
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetGroupList returns the groupID list that the node belongs to
func (c *Client) GetGroupList(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getGroupList")
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetBlockByHash returns the block information according to the given block hash
func (c *Client) GetBlockByHash(ctx context.Context, blockHash common.Hash, onlyHeader, onlyTxHash bool) (*types.Block, error) {
	var block types.Block
	err := c.conn.CallContext(ctx, &block, "getBlockByHash", c.groupID, blockHash.Hex(), onlyHeader, onlyTxHash)
	if err != nil {
		return nil, err
	}
	return &block, err
}

// GetBlockByNumber returns the block information according to the given block number(hex format)
func (c *Client) GetBlockByNumber(ctx context.Context, blockNumber int64, onlyHeader, onlyTxHash bool) (*types.Block, error) {
	var block types.Block
	if blockNumber < 0 {
		return nil, errors.New("invalid negative block number")
	}
	err := c.conn.CallContext(ctx, &block, "getBlockByNumber", c.groupID, blockNumber, onlyHeader, onlyTxHash)
	if err != nil {
		return nil, err
	}
	return &block, err
}

// GetBlockHashByNumber returns the block hash according to the given block number
func (c *Client) GetBlockHashByNumber(ctx context.Context, blockNumber int64) (*common.Hash, error) {
	if blockNumber < 0 {
		return nil, errors.New("invalid negative block number")
	}
	var raw string
	err := c.conn.CallContext(ctx, &raw, "getBlockHashByNumber", c.groupID, blockNumber)
	if err != nil {
		return nil, err
	}
	blockHash := common.HexToHash(raw)
	return &blockHash, err
}

// GetTransactionByHash returns the transaction information according to the given transaction hash
func (c *Client) GetTransactionByHash(ctx context.Context, txHash common.Hash, withProof bool) (*types.TransactionDetail, error) {
	var transactionDetail types.TransactionDetail
	err := c.conn.CallContext(ctx, &transactionDetail, "getTransactionByHash", c.groupID, txHash.String(), withProof)
	if err != nil {
		return nil, err
	}
	return &transactionDetail, err
}

// GetTransactionReceipt returns the transaction receipt according to the given transaction hash
func (c *Client) GetTransactionReceipt(ctx context.Context, txHash common.Hash, withProof bool) (*types.Receipt, error) {
	var raw *types.Receipt
	var anonymityReceipt = &struct {
		types.Receipt
	}{}
	err := c.conn.CallContext(ctx, anonymityReceipt, "getTransactionReceipt", c.groupID, txHash.String(), withProof)
	if err != nil {
		return nil, err
	}
	//if len(anonymityReceipt.Status) < 2 {
	//	return nil, fmt.Errorf("transaction %v is not on-chain", txHash.Hex())
	//}
	//status, err := strconv.ParseInt(anonymityReceipt.Status[2:], 16, 32)
	//if err != nil {
	//	return nil, fmt.Errorf("GetTransactionReceipt failed, strconv.ParseInt err: " + fmt.Sprint(err))
	//}
	raw = &anonymityReceipt.Receipt
	//raw.Status = int(status)
	return raw, err
}

// GetContractAddress returns a contract address according to the transaction hash
func (c *Client) GetContractAddress(ctx context.Context, txHash common.Hash) (common.Address, error) {
	var raw interface{}
	var contractAddress common.Address
	err := c.conn.CallContext(ctx, &raw, "getTransactionReceipt", c.groupID, txHash.Hex(), false)
	if err != nil {
		return contractAddress, err
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return contractAddress, fmt.Errorf("GetContractAddress Json respond does not satisfy the type assertion: map[string]interface{}, %+v", raw)
	}
	var temp interface{}
	temp, ok = m["contractAddress"]
	if !ok {
		return contractAddress, errors.New("json respond does not contains the key `contractAddress`")
	}
	var strContractAddress string
	strContractAddress, ok = temp.(string)
	if !ok {
		return contractAddress, errors.New("type assertion for Chain Id is wrong: not a string")
	}
	return common.HexToAddress(strContractAddress), nil
}

// GetPendingTransactions returns information of the pending transactions
func (c *Client) GetPendingTransactions(ctx context.Context) (*[]types.TransactionPending, error) {
	var pendingTransactions []types.TransactionPending
	err := c.conn.CallContext(ctx, &pendingTransactions, "getPendingTransactions", c.groupID)
	if err != nil {
		return nil, err
	}
	return &pendingTransactions, err
}

// GetPendingTxSize returns amount of the pending transactions
func (c *Client) GetPendingTxSize(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getPendingTxSize", c.groupID)
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetCode returns the contract code according to the contract address
func (c *Client) GetCode(ctx context.Context, address common.Address) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getCode", c.groupID, strings.ToLower(address.String()[2:]))
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetTotalTransactionCount returns the total amount of transactions and the block height at present
func (c *Client) GetTotalTransactionCount(ctx context.Context) (*types.TransactionCount, error) {
	var transactionCount types.TransactionCount
	err := c.conn.CallContext(ctx, &transactionCount, "getTotalTransactionCount", c.groupID)
	if err != nil {
		return nil, err
	}
	return &transactionCount, err
}

func (c *Client) GetGroupNodeInfo(ctx context.Context, nodeId string) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getGroupNodeInfo", c.groupID, nodeId)
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

func (c *Client) GetGroupInfo(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getGroupInfo", c.groupID)
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetSystemConfigByKey returns value according to the key(only tx_count_limit, tx_gas_limit could work)
func (c *Client) GetSystemConfigByKey(ctx context.Context, configKey string) (*types.SystemConfig, error) {
	var raw types.SystemConfig
	err := c.conn.CallContext(ctx, &raw, "getSystemConfigByKey", c.groupID, configKey)
	if err != nil {
		return nil, err
	}
	//js, err := json.MarshalIndent(raw, "", indent)
	return &raw, err
}

func getVersionNumber(strVersion string) (int, error) {
	strList := strings.Split(strVersion, ".")
	if len(strList) != 3 {
		return 0, fmt.Errorf("strList length must be 3")
	}
	var versionNumber int
	for i := 0; i < len(strList); i++ {
		num, err := strconv.Atoi(strList[i])
		if err != nil {
			return 0, fmt.Errorf("getVersionNumber failed, err: %v", err)
		}
		versionNumber += num
		versionNumber = versionNumber << 8
	}
	return versionNumber, nil
}
