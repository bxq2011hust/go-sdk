package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"github.com/FISCO-BCOS/go-sdk/abi"
	"github.com/FISCO-BCOS/go-sdk/abi/bind"
	"github.com/FISCO-BCOS/go-sdk/conf"
	"github.com/FISCO-BCOS/go-sdk/core/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type BcosSDK struct {
	Callback PostCallback
	config   *conf.Config
	backend  *ContractProxy
	auth     *bind.TransactOpts
	callOpts *bind.CallOpts
}

// PostCallback delegate callback function, will implement in outside objc code
type PostCallback interface {
	SendRequest(rpcRequest string) string
}

// BuildSDKResult return when build sdk
type BuildSDKResult struct {
	IsSuccess   bool   `json:"isSuccess"`
	Information string `json:"information"`
}

// ReceiptResult return by deploy and sendTransaction function.
type ReceiptResult struct {
	Code    int
	Message string
	Receipt *TxReceipt
}

// TransactionResult result with transaction
type TransactionResult struct {
	Code        int
	Message     string
	Transaction *FullTransaction
}

// CallResult return by call function
type CallResult struct {
	Code    int
	Message string
	Result  string
}

// RPCResult return by rpc request
type RPCResult struct {
	Code    int
	Message string
	Result  string
}

// ContractParams Parameters
type ContractParams struct {
	ValueType string      `json:"type"`
	Value     interface{} `json:"value"`
}

type TxReceipt struct {
	TransactionHash  string `json:"transactionHash"`
	TransactionIndex string `json:"transactionIndex"`
	BlockHash        string `json:"blockHash"`
	BlockNumber      string `json:"blockNumber"`
	GasUsed          string `json:"gasUsed"`
	ContractAddress  string `json:"contractAddress"`
	Root             string `json:"root"`
	Status           int    `json:"status"`
	From             string `json:"from"`
	To               string `json:"to"`
	Input            string `json:"input"`
	Output           string `json:"output"`
	Logs             string `json:"logs"`
	LogsBloom        string `json:"logsBloom"`
}

type FullTransaction struct {
	BlockHash        string `json:"blockHash"`
	BlockNumber      string `json:"blockNumber"`
	From             string `json:"from"`
	Gas              string `json:"gas"`
	GasPrice         string `json:"gasPrice"`
	Hash             string `json:"hash"`
	Input            string `json:"input"`
	Nonce            string `json:"nonce"`
	To               string `json:"to"`
	TransactionIndex string `json:"transactionIndex"`
	Value            string `json:"value"`
}

// NetworkResponse data type return from the post callback
type NetworkResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Result  json.RawMessage `json:"data"`
}

// BuildSDKWithParam
// Connect to the proxy or FISCO BCOS node.
// Please make sure ca.crt, sdk.crt, sdk.key under path certPath.
// Please provider full keyFile path
func (sdk *BcosSDK) BuildSDKWithParam(keyFile string, groupID int, chainID int64, isSMCrypto bool, callback PostCallback) *BuildSDKResult {
	// init config and callback
	config, err := conf.ParseConfigOptions("", "", "", keyFile, groupID, "", true, chainID, isSMCrypto)
	if err != nil {
		return &BuildSDKResult{false, err.Error()}
	}
	sdk.config = config
	sdk.Callback = callback

	// Init transact auth and
	sdk.auth = bind.NewSMCryptoTransactor(sdk.config.PrivateKey)
	if config.IsSMCrypto {
		sdk.auth = bind.NewSMCryptoTransactor(config.PrivateKey)
	} else {
		privateKey, err := crypto.ToECDSA(config.PrivateKey)
		if err != nil {
			return &BuildSDKResult{false, err.Error()}
		}
		sdk.auth = bind.NewKeyedTransactor(privateKey)
	}
	sdk.auth.GasLimit = big.NewInt(30000000)
	sdk.auth.GasPrice = big.NewInt(30000000)
	sdk.callOpts = &bind.CallOpts{From: sdk.auth.From}

	// Init backend
	sdk.backend = &ContractProxy{
		groupID:  groupID,
		chainID:  big.NewInt(chainID),
		callback: sdk.Callback,
	}
	return &BuildSDKResult{true, "Init success"}
}

// DeployContract is a function to deploy a FISCO BCOS smart contract
// Return receipt
func (sdk *BcosSDK) DeployContract(contractAbi string, contractBin string, params string) *ReceiptResult {
	parsedAbi, err := abi.JSON(strings.NewReader(contractAbi))
	if err != nil {
		return toReceiptResult(nil, errors.New("your abi is not a right json string: "+err.Error()))
	}
	goParam, err := toGoParams(params)
	if err != nil {
		return toReceiptResult(nil, errors.New("params error: "+err.Error()))
	}
	_, receipt, _, err := bind.DeployContractGetReceipt(sdk.auth, parsedAbi, common.FromHex(contractBin), sdk.backend, goParam...)
	return toReceiptResult(receipt, err)
}

// SendTransaction is a function to send an transaction to call smart contract function.
// return receipt
func (sdk *BcosSDK) SendTransaction(contractAbi string, address string, method string, params string) *ReceiptResult {
	parsed, err := abi.JSON(strings.NewReader(contractAbi))
	if err != nil {
		return toReceiptResult(nil, errors.New("your abi is not a right json string: "+err.Error()))
	}
	goParams, err := toGoParams(params)
	if err != nil {
		return toReceiptResult(nil, errors.New("params error: "+err.Error()))
	}
	addr := common.HexToAddress(address)
	boundContract := bind.NewBoundContract(addr, parsed, sdk.backend, sdk.backend, sdk.backend)
	_, receipt, err := boundContract.Transact(sdk.GetTransactOpts(), method, goParams...)
	return toReceiptResult(receipt, err)
}

// Call is a function to call a smart contract function without sending transaction
// return CallResult
func (sdk *BcosSDK) Call(abiContract string, address string, method string, params string, outputNum int) *CallResult {
	parsed, err := abi.JSON(strings.NewReader(abiContract))
	if err != nil {
		return toCallResult("", errors.New("your abi is not a right json string: "+err.Error()))
	}
	goParams, err := toGoParams(params)
	if err != nil {
		return toCallResult("", errors.New("params error: "+err.Error()))
	}
	addr := common.HexToAddress(address)
	boundContract := bind.NewBoundContract(addr, parsed, sdk.backend, sdk.backend, sdk.backend)

	if outputNum > 1 {
		var result = make([]interface{}, outputNum)
		err = boundContract.Call(sdk.GetCallOpts(), &result, method, goParams...)
		if err != nil {
			return toCallResult("", errors.New("call contract error: "+err.Error()))
		}
		resultBytes, err := json.Marshal(result)
		if err != nil {
			return toCallResult("", errors.New(": "+err.Error()))
		}
		return toCallResult(string(resultBytes), err)
	} else {
		var result interface{}
		err = boundContract.Call(sdk.GetCallOpts(), &result, method, goParams...)
		if err != nil {
			return toCallResult("", errors.New("call contract error: "+err.Error()))
		}
		resultBytes, err := json.Marshal(result)
		if err != nil {
			return toCallResult("", errors.New(": "+err.Error()))
		}
		return toCallResult(string(resultBytes), err)
	}
}

// RPC calls
// GetClientVersion is to query the client version of connected nodes
func (sdk *BcosSDK) GetClientVersion() *RPCResult {
	var raw interface{}
	if err := sdk.backend.CallContext(context.TODO(), &raw, "getClientVersion"); err != nil {
		return toRPCResult("", err)
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return toRPCResult(string(js), err)
}

// GetBlockNumber is to query the blockchain and get the latest block number.
// Return the latest block number
func (sdk *BcosSDK) GetBlockNumber() *RPCResult {
	var raw string
	if err := sdk.backend.CallContext(context.TODO(), &raw, "getBlockNumber", sdk.backend.groupID); err != nil {
		return toRPCResult("", err)
	}
	blockNumber, err := strconv.ParseInt(raw, 0, 64)
	if err != nil {
		return toRPCResult("", fmt.Errorf("parse block number failed, err: %v", err))
	}
	return toRPCResult(strconv.FormatInt(blockNumber, 10), err)
}

// GetTransactionByHash is to query the blockchain and get the transaction of a transaction hash.
// Get transaction by tx hash
func (sdk *BcosSDK) GetTransactionByHash(txHash string) *TransactionResult {
	var raw FullTransaction
	err := sdk.backend.CallContext(context.TODO(), &raw, "getTransactionByHash", sdk.backend.groupID, txHash)
	return toTransactionResult(&raw, err)
}

// GetTransactionReceipt is to query the blockchain and get the receipt of a transaction.
func (sdk *BcosSDK) GetTransactionReceipt(txHash string) *ReceiptResult {
	var anonymityReceipt = &struct {
		types.Receipt
		Status string `json:"status"`
	}{}
	err := sdk.backend.CallContext(context.TODO(), &anonymityReceipt, "getTransactionReceipt", sdk.backend.groupID, txHash)
	if err != nil {
		return toReceiptResult(nil, errors.New("call rpc error: "+err.Error()))
	}
	status, err := strconv.ParseInt(anonymityReceipt.Status[2:], 16, 32)
	if err != nil {
		return toReceiptResult(nil, errors.New("call rpc error: parse int of receipt status error: "+err.Error()))
	}

	// parse to types.Receipt
	receipt := &anonymityReceipt.Receipt
	receipt.Status = int(status)
	return toReceiptResult(receipt, nil)
}

// GetTransactOpts return *bind.TransactOpts
func (sdk *BcosSDK) GetTransactOpts() *bind.TransactOpts {
	return sdk.auth
}

// GetCallOpts return *bind.CallOpts
func (sdk *BcosSDK) GetCallOpts() *bind.CallOpts {
	return sdk.callOpts
}

func toGoParams(param string) ([]interface{}, error) {
	var objs []ContractParams
	if err := json.Unmarshal([]byte(param), &objs); err != nil {
		return nil, err
	}
	var par []interface{}

	for _, t := range objs {
		value, err := stringToInterface(t.ValueType, t.Value)
		if err != nil {
			return nil, err
		}
		par = append(par, value)
	}
	return par, nil
}

func toTransactionResult(transaction *FullTransaction, err error) *TransactionResult {
	var txResult TransactionResult
	if err != nil {
		txResult.Code = -1
		txResult.Message = err.Error()
	}
	if transaction != nil {
		txResult.Transaction = transaction
	}
	return &txResult
}

func toReceiptResult(receipt *types.Receipt, err error) *ReceiptResult {
	var receiptResult ReceiptResult
	if err != nil {
		receiptResult.Code = -1
		receiptResult.Message = err.Error()
		return &receiptResult
	}
	if receipt != nil {
		rec, err := toReceipt(receipt)
		receiptResult.Receipt = rec
		if err != nil {
			receiptResult.Code = -1
			receiptResult.Message = err.Error()
			return &receiptResult
		}
	} else {
		receiptResult.Code = -1
		receiptResult.Message = "No result"
	}
	return &receiptResult
}

func toReceipt(_r *types.Receipt) (*TxReceipt, error) {
	if _r == nil {
		return nil, errors.New("receipt is null")
	}
	var rec TxReceipt
	rec.TransactionHash = _r.TransactionHash
	rec.TransactionIndex = _r.TransactionIndex
	rec.BlockHash = _r.BlockHash
	rec.BlockNumber = _r.BlockNumber
	rec.GasUsed = _r.GasUsed
	rec.ContractAddress = _r.ContractAddress.Hex()
	rec.Root = _r.Root
	rec.Status = _r.Status
	rec.From = _r.From
	rec.To = _r.To
	rec.Input = _r.Input
	rec.Output = _r.Output
	logs, err := json.Marshal(_r.Logs)
	rec.Logs = string(logs)
	rec.LogsBloom = _r.LogsBloom
	return &rec, err
}

func toCallResult(result string, err error) *CallResult {
	if err != nil {
		return &CallResult{
			Code:    -1,
			Message: err.Error(),
		}
	}
	return &CallResult{
		Code:   0,
		Result: result,
	}
}

func toRPCResult(result string, err error) *RPCResult {
	if err != nil {
		return &RPCResult{
			Code:    -1,
			Message: err.Error(),
		}
	}
	return &RPCResult{
		Code:    0,
		Message: "",
		Result:  result,
	}
}

// interface to string
func interfaceToString(param []interface{}) ([]string, error) {
	var str []string
	for _, p := range param {
		switch p.(type) {
		case string:
			str = append(str, p.(string))
		case int:
			str = append(str, strconv.FormatInt(int64(p.(int)), 10))
		case int8:
			str = append(str, strconv.FormatInt(int64(p.(int8)), 10))
		case int16:
			str = append(str, strconv.FormatInt(int64(p.(int16)), 10))
		case int32:
			str = append(str, strconv.FormatInt(int64(p.(int32)), 10))
		case int64:
			str = append(str, strconv.FormatInt(p.(int64), 10))
		case uint:
			str = append(str, strconv.FormatUint(p.(uint64), 10))
		case uint8:
			str = append(str, strconv.FormatUint(uint64(p.(uint8)), 10))
		case uint16:
			str = append(str, strconv.FormatUint(uint64(p.(uint16)), 10))
		case uint32:
			str = append(str, strconv.FormatUint(uint64(p.(uint32)), 10))
		case uint64:
			str = append(str, strconv.FormatUint(p.(uint64), 10))
		case bool:
			str = append(str, strconv.FormatBool(p.(bool)))
		case []byte:
			str = append(str, string(p.([]byte)))
		case common.Address:
			str = append(str, p.(common.Address).Hex())
		default:
			return nil, errors.New("unsupport interface type (" + reflect.TypeOf(p).String() + ")")
		}
	}
	return str, nil
}

// string to interface
func stringToInterface(paramType string, value interface{}) (interface{}, error) {
	if strings.Count(paramType, "[") != 0 {
		// split elements
		i := strings.LastIndex(paramType, "[")
		preType := paramType[:i]
		valueList, ok := value.([]interface{})
		if !ok {
			return nil, errors.New("parse data to interface error")
		}

		// get type and construct an array
		obj, err := stringToInterfaceBasic(preType, valueList[0])
		if err != nil {
			return nil, err
		}

		// construct array
		arrayType := reflect.ArrayOf(len(valueList), reflect.TypeOf(obj))
		array := reflect.New(arrayType).Elem()
		for i, one := range valueList {
			obj, err := stringToInterfaceBasic(preType, one)
			if err != nil {
				return nil, err
			}
			if array.Index(i).Kind() == reflect.Ptr {
				newObj := reflect.New(array.Index(i).Type().Elem())
				array.Index(i).Set(newObj)
				if err := set(newObj, reflect.ValueOf(obj)); err != nil {
					return nil, errors.New("parse params error :" + err.Error())
				}
			} else {
				if err := set(array.Index(i), reflect.ValueOf(obj)); err != nil {
					return nil, errors.New("parse params error :" + err.Error())
				}
			}
		}
		return array.Interface(), nil
	} else if strings.Count(paramType, "(") != 0 {
		// Identify struct type
		paramTypeString := paramType[1 : len(paramType)-1]
		params := strings.Split(paramTypeString, ",")

		// Get values
		objs := value.(map[string]interface{})
		// Construct a struct
		var fields []reflect.StructField

		i := 0
		for k, v := range objs {
			p, e := stringToInterfaceBasic(params[i], v)
			if e != nil {
				return nil, e
			}
			aField := reflect.StructField{
				Name:    k,
				Type:    reflect.TypeOf(p),
				PkgPath: "github.com/FISCO-BCOS/go-sdk/mobile/ios",
			}
			fields = append(fields, aField)
			i++
		}
		structType := reflect.StructOf(fields)

		// Init struct
		structInstance := reflect.New(structType).Elem()
		i = 0
		for k, v := range objs {
			p, e := stringToInterfaceBasic(params[i], v)
			if e != nil {
				return nil, e
			}

			aField := structInstance.FieldByName(k)
			if aField.Kind() == reflect.Ptr {
				newValue := reflect.NewAt(aField.Type(), unsafe.Pointer(aField.UnsafeAddr()))
				newValue.Elem().Set(reflect.ValueOf(p))
			} else {
				newValue := reflect.NewAt(aField.Type(), unsafe.Pointer(aField.UnsafeAddr()))
				err := set(newValue, reflect.ValueOf(p))
				if err != nil {
					return nil, err
				}
			}
			i++
		}
		return structInstance.Addr().Interface(), nil
	} else {
		return stringToInterfaceBasic(paramType, value)
	}
}

// Parse string params to go interface
func stringToInterfaceBasic(paramType string, value interface{}) (interface{}, error) {
	switch paramType {
	case "string":
		return value, nil
	case "int":
		return int(value.(float64)), nil
	case "int8":
		return int8(value.(float64)), nil
	case "int16":
		return int16(value.(float64)), nil
	case "int32":
		return int32(value.(float64)), nil
	case "int64":
		return int64(value.(float64)), nil
	case "int256":
		in, err := strconv.ParseInt(value.(string), 10, 64)
		if err != nil {
			return nil, err
		}
		return big.NewInt(in), nil
	case "uint":
		return uint(value.(float64)), nil
	case "uint8":
		return uint8(value.(float64)), nil
	case "uint16":
		return uint16(value.(float64)), nil
	case "uint32":
		return uint32(value.(float64)), nil
	case "uint64":
		return uint64(value.(float64)), nil
	case "uint256":
		in, err := strconv.ParseUint(value.(string), 10, 64)
		if err != nil {
			return nil, err
		}
		return big.NewInt(int64(in)), nil
	case "bool":
		return value.(bool), nil
	case "[]byte", "bytes":
		byteValue := common.FromHex(value.(string))
		result := make([]byte, len(byteValue))
		copy(result[:], byteValue)
		return result, nil
	case "bytes1", "bytes2", "bytes3", "bytes4", "bytes5", "bytes6", "bytes7", "bytes8", "bytes9", "bytes10", "bytes11", "bytes12", "bytes13", "bytes14", "bytes15", "bytes16", "bytes17", "bytes18", "bytes19", "bytes20", "bytes21", "bytes22", "bytes23", "bytes24", "bytes25", "bytes26", "bytes27", "bytes28", "bytes29", "bytes30", "bytes31", "bytes32":
		length, err := strconv.ParseInt(paramType[5:], 10, 8)
		if err != nil {
			return nil, err
		}
		byteValue := common.FromHex(value.(string))
		result := make([]byte, length)
		copy(result[:], byteValue)
		return mustByteSliceToArray(reflect.ValueOf(result)).Interface(), nil
	case "address":
		result := common.HexToAddress(value.(string))
		return result, nil
	default:
		err := fmt.Errorf("unsupport interface type (" + paramType + ")")
		return value, err
	}
}

// abi.typ to interface
func getGoType(kind abi.Type) interface{} {
	switch kind.T {
	case abi.AddressTy:
		var result *common.Address
		return result
	case abi.IntTy, abi.UintTy:
		parts := regexp.MustCompile(`(u)?int([0-9]*)`).FindStringSubmatch(kind.String())
		if parts[1] == "u" {
			switch parts[2] {
			case "8":
				return new(uint8)
			case "16":
				return new(uint16)
			case "32":
				return new(uint32)
			case "64":
				return new(uint64)
			case "256":
				return new(*big.Int)
			}
		} else {
			switch parts[2] {
			case "8":
				return new(int8)
			case "16":
				return new(int16)
			case "32":
				return new(int32)
			case "64":
				return new(int64)
			case "256":
				return new(*big.Int)
			}
		}
	case abi.FixedBytesTy:
		return new([]byte)
	case abi.BytesTy:
		return new([]byte)
	case abi.FunctionTy:
		return new([24]byte)
	case abi.BoolTy:
		return new(bool)
	case abi.StringTy:
		return new(string)
	case abi.HashTy:
		return new(common.Hash)
	default:
		return new(interface{})
	}
	return nil
}

func set(dst, src reflect.Value) error {
	dstType, srcType := dst.Type(), src.Type()
	switch {
	case dstType.Kind() == reflect.Interface && dst.Elem().IsValid():
		return set(dst.Elem(), src)
	case dstType.Kind() == reflect.Ptr && src.Kind() == reflect.Ptr:
		return set(dst.Elem(), src.Elem())
	case dstType.Kind() == reflect.Ptr:
		return set(dst.Elem(), src)
	case srcType.AssignableTo(dstType) && dst.CanSet():
		dst.Set(src)
	case dstType.Kind() == reflect.Slice && srcType.Kind() == reflect.Slice:
		return setSlice(dst, src)
	default:
		//return fmt.Errorf("abi: cannot unmarshal %v in to %v", src.Type(), dst.Type())
	}
	return nil
}

func setSlice(dst, src reflect.Value) error {
	slice := reflect.MakeSlice(dst.Type(), src.Len(), src.Len())
	for i := 0; i < src.Len(); i++ {
		v := src.Index(i)
		reflect.Copy(slice.Index(i), v)
	}
	dst.Set(slice)
	return nil
}
func mustByteSliceToArray(value reflect.Value) reflect.Value {
	arrayType := reflect.ArrayOf(value.Len(), reflect.TypeOf(uint8(0)))
	array := reflect.New(arrayType).Elem()
	for i := 0; i < value.Len(); i++ {
		array.Index(i).Set(value.Index(i))
	}
	return array
}

func toDecimal(hex string) (int, error) {
	i := new(big.Int)
	var flag bool
	i, flag = i.SetString(hex, 16) // octal
	if !flag {
		return -1, fmt.Errorf("Cannot parse hex string to Int")
	}
	return int(i.Uint64()), nil
}