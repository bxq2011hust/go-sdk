# !/bin/bash

set -e

start_time=15
macOS=
ldflags="-ldflags=\"-r /usr/local/lib/bcos-c-sdk/libs/linux\""
check_amop=
GOPATH_BIN=$(go env GOPATH)/bin
SHELL_FOLDER=$(
    cd $(dirname $0)
    pwd
)

LOG_ERROR() {
    content=${1}
    echo -e "\033[31m${content}\033[0m"
}

LOG_INFO() {
    content=${1}
    echo -e "\033[32m[INFO] ${content}\033[0m"
}

execute_cmd() {
    command="${1}"
    eval ${command}
    ret=$?
    if [ $ret -ne 0 ]; then
        LOG_ERROR "FAILED of command: ${command}"
        exit 1
    else
        LOG_INFO "SUCCESS of command: ${command}"
    fi
}

check_env(){
    if [ "$(uname)" == "Darwin" ];then
        # export PATH="/usr/local/opt/openssl/bin:$PATH"
        ldflags="-ldflags=\"-r /usr/local/lib/bcos-c-sdk/libs/darwin\""
        macOS="macOS"
    fi
    export GODEBUG=cgocheck=0
    go install golang.org/x/tools/cmd/goimports@latest || true
    go get golang.org/x/tools/cmd/goimports || true
}

compile_and_ut()
{
    export GO111MODULE="on"
    execute_cmd "go build cmd/console.go"
    execute_cmd "go build -o abigen ./cmd/abigen/main.go"

    execute_cmd "go test -v ./smcrypto"
}

generate_main_gm() {
    local struct="${1}"
    local output="${2}"
cat << EOF >> "${output}"

func main() {
	privateKey, _ := hex.DecodeString("389bb3e29db735b5dc4f114923f1ac5136891efda282a18dc0768e34305c861b")
	config := &conf.Config{IsSMCrypto: true, GroupID: "group0", PrivateKey: privateKey, NodeURL: "127.0.0.1:20200"}
	client, err := client.Dial(config)
	if err != nil {
		fmt.Printf("Dial Client failed, err:%v", err)
		return
	}
	address, _, instance, err := Deploy${struct}(client.GetTransactOpts(), client)
	if err != nil {
		fmt.Printf("Deploy failed, err:%v", err)
		return
	}
	fmt.Println("contract address: ", address.Hex()) // the address should be saved
	//fmt.Println("transaction hash: ", tx.Hash().Hex())
EOF
}

generate_main() {
    local struct="${1}"
    local output="${2}"
cat << EOF >> "${output}"

func main() {
	privateKey, _ := hex.DecodeString("b89d42f12290070f235fb8fb61dcf96e3b11516c5d4f6333f26e49bb955f8b62")
	config := &conf.Config{IsSMCrypto: false, GroupID: "group0",
	          PrivateKey: privateKey, NodeURL: "127.0.0.1:20200"}

	client, err := client.Dial(config)
	if err != nil {
		fmt.Printf("Dial Client failed, err:%v", err)
		return
	}
	address, _, instance, err := Deploy${struct}(client.GetTransactOpts(), client)
	if err != nil {
		fmt.Printf("Deploy failed, err:%v", err)
		return
	}
	fmt.Println("contract address: ", address.Hex()) // the address should be saved
	//fmt.Println("transaction hash: ", tx.Hash().Hex())
EOF
}

generate_hello() {
    local struct="${1}"
    local output="${2}"
    generate_main "${1}" "${2}"
cat << EOF >> "${output}"

	hello := &${struct}Session{Contract: instance, CallOpts: *client.GetCallOpts(), TransactOpts: *client.GetTransactOpts()}
	ret, err := hello.Get()
	if err != nil {
		fmt.Printf("hello.Get() failed: %v", err)
		return
	}
    done := make(chan bool)
	err = hello.WatchAllSetValue(nil, func(ret int, logs []types.Log) {
		fmt.Printf("WatchAllSetValue receive statud: %d, logs: %v\n", ret, logs)
        setValue, err := hello.ParseSetValue(logs[0])
		if err != nil {
			fmt.Printf("hello.WatchAllSetValue() failed: %v", err)
			panic("WatchAllSetValue hello.WatchAllSetValue() failed")
		}
		fmt.Printf("receive setValue: %+v\n", *setValue)
		done <- true
	})
	if err != nil {
		fmt.Printf("hello.WatchAllSetValue() failed: %v", err)
		return
	}
	fmt.Printf("Get: %s\n", ret)
	_, _, err = hello.Set("fisco")
	if err != nil {
		fmt.Printf("hello.Set failed: %v", err)
		return
	}
	ret, err = hello.Get()
	if err != nil {
		fmt.Printf("hello.Get() failed: %v", err)
		return
	}
	fmt.Printf("Get: %s\n", ret)
    <-done
    from := common.HexToAddress("0x83309d045a19c44Dc3722D15A6AbD472f95866aC")
	hello.WatchSetValue(nil, func(ret int, logs []types.Log) {
		fmt.Printf("WatchSetValue receive statud: %d, logs: %+v\n", ret, logs)
		setValue, err := hello.ParseSetValue(logs[0])
		if err != nil {
			fmt.Printf("hello.WatchSetValue() failed: %v", err)
			panic("hello.WatchSetValue() failed")
		}
		fmt.Printf("WatchSetValue receive setValue: %+v\n", *setValue)
		done <- true
	}, from, from)
	<-done
}
EOF
    "${GOPATH_BIN}"/goimports -w  "${output}"
}

generate_hello_gm() {
    local struct="${1}"
    local output="${2}"
    generate_main_gm "${1}" "${2}"
cat << EOF >> "${output}"

	hello := &${struct}Session{Contract: instance, CallOpts: *client.GetCallOpts(), TransactOpts: *client.GetTransactOpts()}
	ret, err := hello.Get()
	if err != nil {
		fmt.Printf("hello.Get() failed: %v", err)
		return
	}
    done := make(chan bool)
	err = hello.WatchAllSetValue(nil, func(ret int, logs []types.Log) {
		fmt.Printf("WatchAllSetValue receive statud: %d, logs: %v\n", ret, logs)
        setValue, err := hello.ParseSetValue(logs[0])
		if err != nil {
			fmt.Printf("hello.WatchAllSetValue() failed: %v", err)
			panic("WatchAllSetValue hello.WatchAllSetValue() failed")
		}
		fmt.Printf("receive setValue: %+v\n", *setValue)
		done <- true
	})
	if err != nil {
		fmt.Printf("hello.WatchAllSetValue() failed: %v", err)
		return
	}
	fmt.Printf("Get: %s\n", ret)
	_, _, err = hello.Set("fisco")
	if err != nil {
		fmt.Printf("hello.Set failed: %v", err)
		return
	}
	ret, err = hello.Get()
	if err != nil {
		fmt.Printf("hello.Get() failed: %v", err)
		return
	}
	fmt.Printf("Get: %s\n", ret)
    <-done
    from := common.HexToAddress("0x000000000000000000000000791a0073e6dfd9dc5e5061aebc43ab4f7aa4ae8b")
	hello.WatchSetValue(nil, func(ret int, logs []types.Log) {
		fmt.Printf("WatchSetValue receive statud: %d, logs: %+v\n", ret, logs)
		setValue, err := hello.ParseSetValue(logs[0])
		if err != nil {
			fmt.Printf("hello.WatchSetValue() failed: %v", err)
			panic("hello.WatchSetValue() failed")
		}
		fmt.Printf("WatchSetValue receive setValue: %+v\n", *setValue)
		done <- true
	}, from, from)
	<-done
}
EOF
    "${GOPATH_BIN}"/goimports -w  "${output}"
}

generate_counter() {
    local struct="${1}"
    local output="${2}"
    generate_main "${1}" "${2}"
cat << EOF >> "${output}"

	counter := &${struct}Session{Contract: instance, CallOpts: *client.GetCallOpts(), TransactOpts: *client.GetTransactOpts()}
	ret, err := counter.Get()
	if err != nil {
		fmt.Printf("counter.Get() failed: %v", err)
		return
	}
	fmt.Printf("Get: %d\n", ret)
	_, _, err = counter.Set(big.NewInt(111))
	if err != nil {
		fmt.Printf("counter.Set failed: %v", err)
		return
	}
	ret, err = counter.Get()
	if err != nil {
		fmt.Printf("counter.Get() failed: %v", err)
		return
	}
	if big.NewInt(111).Cmp(ret) != 0 {
		fmt.Printf("counter.Set() failed, expected 111 (got %d)", ret)
		return
	}
	fmt.Printf("Get: %s\n", ret)
	ret, err = counter.Version()
	if err != nil {
		fmt.Printf("counter.Version() failed: %v", err)
		return
	}
	if big.NewInt(0).Cmp(ret) != 0 {
		fmt.Printf("counter.Version() failed, expected 0 (got %d)", ret)
		return
	}
	_, _, err = counter.Add()
	if err != nil {
		fmt.Printf("counter.Add() failed: %v", err)
		return
	}
	ret, err = counter.Get()
	if err != nil {
		fmt.Printf("counter.Get() failed: %v", err)
		return
	}
	if big.NewInt(112).Cmp(ret) != 0 {
		fmt.Printf("counter.Add() failed, expected 111 (got %d)", ret)
		return
	}
}

EOF
    "${GOPATH_BIN}"/goimports -w  "${output}"
}

get_build_chain()
{
    latest_version="v3.0.1"
    curl -#LO https://github.com/FISCO-BCOS/FISCO-BCOS/releases/download/"${latest_version}"/build_chain.sh && chmod u+x build_chain.sh
    curl -#LO https://github.com/FISCO-BCOS/FISCO-BCOS/releases/download/"${latest_version}"/build_chain.sh && chmod u+x build_chain.sh
}

get_csdk_lib()
{
    #latest_version=$(curl -sS https://gitee.com/api/v5/repos/FISCO-BCOS/FISCO-BCOS/tags | grep -oe "\"name\":\"v[2-9]*\.[0-9]*\.[0-9]*\"" | cut -d \" -f 4 | sort -V | tail -n 1)
    curl -#LO https://github.com/yinghuochongfly/bcos-c-sdk/releases/download/v3.0.1-rc4/libbcos-c-sdk.so
    curl -#LO https://github.com/yinghuochongfly/bcos-c-sdk/releases/download/v3.0.1-rc4/libbcos-c-sdk.so
    curl -#LO https://github.com/yinghuochongfly/bcos-c-sdk/releases/download/v3.0.1-rc4/libbcos-c-sdk-x86_64.dylib
    sudo mkdir /usr/local/lib/bcos-c-sdk
    sudo mkdir /usr/local/lib/bcos-c-sdk/libs
    sudo mkdir /usr/local/lib/bcos-c-sdk/libs/linux/
    sudo mkdir /usr/local/lib/bcos-c-sdk/libs/darwin/
    sudo mkdir /usr/local/lib/bcos-c-sdk/libs/win/
    sudo cp libbcos-c-sdk.so /usr/local/lib/bcos-c-sdk/libs/linux/
    sudo cp libbcos-c-sdk-x86_64.dylib /usr/local/lib/bcos-c-sdk/libs/darwin/
    sudo cp libbcos-c-sdk-x86_64.dylib /usr/local/lib/bcos-c-sdk/libs/darwin/libbcos-c-sdk.dylib
}

precompiled_test(){
    # TODO: consensus test use getSealer first
    # TODO: cns
    # TODO: permission
    precompileds=(config crud)
    for pkg in ${precompileds[*]}; do
        execute_cmd "go test ${ldflags} -v ./precompiled/${pkg}"
    done
}

integration_std()
{
    LOG_INFO "integration_std testing..."
    execute_cmd "bash tools/download_solc.sh -v 0.6.10"

    bash build_chain.sh -v "${latest_version}" -l 127.0.0.1:2 -o nodes
    bash nodes/127.0.0.1/start_all.sh && sleep "${start_time}"
    cp nodes/127.0.0.1/sdk/* ./conf/
    cp -R nodes/127.0.0.1/sdk/ ./client/conf/
    cp -R nodes/127.0.0.1/sdk/ ./precompiled/config/conf/
    cp -R nodes/127.0.0.1/sdk/ ./precompiled/crud/conf/

    # abigen std
    execute_cmd "./solc-0.6.10 --bin --abi --optimize -o .ci/hello .ci/hello/HelloWorld.sol"
    execute_cmd "./abigen --bin .ci/hello/HelloWorld.bin --abi .ci/hello/HelloWorld.abi  --type Hello --pkg main --out=hello.go"
    generate_hello Hello hello.go
    execute_cmd "go build ${ldflags} -o hello hello.go"
    execute_cmd "go build ${ldflags} -o bn256 .ci/ethPrecompiled/bn256.go"
    LOG_INFO "generate hello.go and build hello done."

    precompiled_test
    execute_cmd "go test ${ldflags} -v ./client"

    ./hello > hello.out
    if [ -z "$(grep address hello.out)" ];then LOG_ERROR "std deploy hello contract failed." && cat hello.out && exit 1;fi
    if [ ! -z "$(cat hello.out | grep failed)" ];then LOG_ERROR "call hello failed." && cat hello.out && exit 1;fi
    # if [ ! -z "$(./bn256 | grep failed)" ];then ./bn256 && LOG_ERROR "call bn256 failed." && exit 1;fi

    execute_cmd "./solc-0.6.10 --bin --abi --optimize -o .ci/counter .ci/counter/Counter.sol"
    execute_cmd "./abigen --bin .ci/counter/Counter.bin --abi .ci/counter/Counter.abi  --type Counter --pkg main --out=counter.go"
    generate_counter Counter counter.go
    execute_cmd "go build ${ldflags} -o counter counter.go"
    if [ -z "$(./counter | grep address)" ];then LOG_ERROR "std deploy contract failed." && exit 1;fi
    if [ ! -z "$(./counter | grep failed)" ];then LOG_ERROR "call counter failed." && exit 1;fi
    if [[ "${check_amop}" == "true" ]];then
        integration_amop
    fi
    bash nodes/127.0.0.1/stop_all.sh
    LOG_INFO "integration_std testing pass."
}

integration_gm()
{
    LOG_INFO "integration_gm testing..."
    execute_cmd "bash tools/download_solc.sh -v 0.6.10 -g"

    bash build_chain.sh -v "${latest_version}" -l 127.0.0.1:2 -s -o nodes_gm
    cp -r nodes_gm/127.0.0.1/sdk/* ./conf/
    bash nodes_gm/127.0.0.1/start_all.sh && sleep "${start_time}"

    # abigen gm
    execute_cmd "./solc-0.6.10-gm --bin --abi  --overwrite -o .ci/hello .ci/hello/HelloWorld.sol"
    execute_cmd "./abigen --bin .ci/hello/HelloWorld.bin --abi .ci/hello/HelloWorld.abi --type Hello --pkg main --out=hello_gm.go --smcrypto=true"
    generate_hello_gm Hello hello_gm.go
    execute_cmd "go build ${ldflags} -o hello_gm hello_gm.go"
    execute_cmd "go build ${ldflags} -o bn256_gm .ci/ethPrecompiled/bn256_gm.go"
    LOG_INFO "generate hello_gm.go and build hello_gm done."

    if [ -z "$(./hello_gm | grep address)" ];then LOG_ERROR "gm deploy contract failed." && exit 1;fi
    ./hello_gm > hello.out
    if [ ! -z "$(grep failed hello.out)" ];then LOG_ERROR "gm call hello_gm failed." && cat hello.out && exit 1;fi
    # if [ ! -z "$(./bn256_gm | grep failed)" ];then ./bn256_gm && LOG_ERROR "gm call bn256_gm failed." && exit 1;fi
    # precompiled_test
    bash nodes_gm/127.0.0.1/stop_all.sh
    LOG_INFO "integration_gm testing pass."
}

integration_amop() {
    # nodes should be started
    LOG_INFO "amop unicast testing..."
    execute_cmd "go build ${ldflags} -o subscriber examples/amop/sub/subscriber.go"
    execute_cmd "go build ${ldflags} -o unicast_publisher examples/amop/unicast_pub/publisher.go"
    ./subscriber 127.0.0.1:20201 hello &
    sleep 2
    ./unicast_publisher 127.0.0.1:20200 hello

    LOG_INFO "amop broadcast testing..."
    execute_cmd "go build ${ldflags} -o broadcast_publisher examples/amop/broadcast_pub/publisher.go"
    execute_cmd "go build ${ldflags} -o broadcast_publisher examples/amop/broadcast_pub/publisher.go"
    ./subscriber 127.0.0.1:20201 hello1 &
    sleep 2
    ./broadcast_publisher 127.0.0.1:20200 hello1
}

parse_params()
{
    echo "parse_params $#"
    while getopts "a" option;do
        case $option in
        a) check_amop="true";;
        *) LOG_WARN "invalid option $option";;
        esac
    done
}

main()
{
    check_env
    get_csdk_lib
    compile_and_ut
    get_build_chain

    if [ -z "${macOS}" ];then # linux
        integration_std
        integration_gm
    else
        integration_std
    fi
}

parse_params "$@"
main
