package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/kaspanet/kaspad/app/appmessage"
	"github.com/kaspanet/kaspad/domain/dagconfig"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
	"github.com/kaspanet/kaspad/util/profiling"

	"encoding/hex"

	"github.com/kaspanet/go-secp256k1"
	"github.com/kaspanet/kaspad/infrastructure/os/signal"
	"github.com/kaspanet/kaspad/util"
	"github.com/kaspanet/kaspad/util/panics"

	"github.com/pkg/errors"
)

var shutdown int32 = 0

func main() {

	prefix := dagconfig.DevnetParams.Prefix

	// Insert here the result of genkeypair operation
	myPrivateKey := "39e640b6e94642f00aeee4e10bb3328d7487603092a90844c95fdde2db69ad68"
	myAddressString := "kaspadev:qp52ukce0tm4a39r59j3r7y65gy7anly03l2ge7dnckmtu7jexn7vyukktmny"

	// Some Private / Public keys manipulation
	myAddress, err := util.DecodeAddress(myAddressString, prefix)
	if err != nil {
		panic(err)
	}

	myKeyPair, myPublicKey, err := parsePrivateKeyInKeyPair(myPrivateKey)
	if err != nil {
		panic(err)
	}

	pubKeySerialized, err := myPublicKey.Serialize()
	if err != nil {
		panic(err)
	}

	pubKeyAddr, err := util.NewAddressPublicKey(pubKeySerialized[:], prefix)
	if err != nil {
		panic(err)
	}

	fmt.Println("myPrivateKey: ", myPrivateKey)
	fmt.Println("myKeyPair: ", myKeyPair)
	fmt.Println()
	fmt.Println("myPublicKey: ", myPublicKey)
	fmt.Println("pubKeySerialized: ", pubKeySerialized)
	fmt.Println()
	fmt.Println("myAddress: ", myAddress)
	fmt.Println("pubKeyAddr: ", pubKeyAddr)
	fmt.Println()

	interrupt := signal.InterruptListener()
	configError := parseConfig()
	if configError != nil {
		fmt.Fprintf(os.Stderr, "Error parsing config: %+v", err)
		os.Exit(1)
	}
	defer backendLog.Close()

	defer panics.HandlePanic(log, "main", nil)

	if cfg.Profile != "" {
		profiling.Start(cfg.Profile, log)
	}

	// RPC connection setup
	rpcAddress, err := activeConfig().ActiveNetParams.NormalizeRPCServerAddress(activeConfig().RPCServer)
	if err != nil {
		log.Error("RPC address can't be identified:")
		panic(err)
	}

	//RPC client activation (to communicate with Kaspad)
	client, err := rpcclient.NewRPCClient(rpcAddress)
	if err != nil {
		log.Error("RPC client connection can't be activated:")
		panic(err)
	}

	client.SetTimeout(5 * time.Minute)

	//Fetch UTXOs from address
	availableUtxos, err := fetchAvailableUTXOs(client, myAddressString)
	if err != nil {
		log.Error("Available UTXOs can't be fetched:")
		panic(err)
	}

	fmt.Println("You have " + fmt.Sprint(len(availableUtxos)) + " spendable UTXOs in " + myAddressString + " address")
	fmt.Println()

	selectedUTXOs := []*appmessage.UTXOsByAddressesEntry{}
	for outpoint, utxo := range availableUtxos {
		outpointCopy := outpoint
		selectedUTXOs = append(selectedUTXOs, &appmessage.UTXOsByAddressesEntry{
			Outpoint:  &outpointCopy,
			UTXOEntry: utxo,
		})
	}
	for _, utxo := range selectedUTXOs {
		fmt.Println("Transaction ID: ", utxo.Outpoint.TransactionID)
		fmt.Println("Amount in Sompi: ", utxo.UTXOEntry.Amount)
		fmt.Println()
	}

	// The End
	<-interrupt
	atomic.AddInt32(&shutdown, 1)

}

func parsePrivateKeyInKeyPair(privateKeyHex string) (*secp256k1.SchnorrKeyPair, *secp256k1.SchnorrPublicKey, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error parsing private key hex")
	}
	privateKey, err := secp256k1.DeserializeSchnorrPrivateKeyFromSlice(privateKeyBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error deserializing private key")
	}
	publicKey, err := privateKey.SchnorrPublicKey()
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error generating public key")
	}
	return privateKey, publicKey, nil
}

// Collect spendable UTXOs from address
func fetchAvailableUTXOs(client *rpcclient.RPCClient, address string) (map[appmessage.RPCOutpoint]*appmessage.RPCUTXOEntry, error) {
	getUTXOsByAddressesResponse, err := client.GetUTXOsByAddresses([]string{address})
	if err != nil {
		return nil, err
	}
	dagInfo, err := client.GetBlockDAGInfo()
	if err != nil {
		return nil, err
	}

	spendableUTXOs := make(map[appmessage.RPCOutpoint]*appmessage.RPCUTXOEntry, 0)
	for _, entry := range getUTXOsByAddressesResponse.Entries {
		if !isUTXOSpendable(entry, dagInfo.VirtualDAAScore) {
			continue
		}
		spendableUTXOs[*entry.Outpoint] = entry.UTXOEntry
	}
	return spendableUTXOs, nil
}

// Verify UTXO is spendable (check if a minimum of 10 confirmations have been processed since UTXO creation)
func isUTXOSpendable(entry *appmessage.UTXOsByAddressesEntry, virtualSelectedParentBlueScore uint64) bool {
	blockDAAScore := entry.UTXOEntry.BlockDAAScore
	if !entry.UTXOEntry.IsCoinbase {
		const minConfirmations = 10
		return blockDAAScore+minConfirmations < virtualSelectedParentBlueScore
	}
	coinbaseMaturity := activeConfig().ActiveNetParams.BlockCoinbaseMaturity
	return blockDAAScore+coinbaseMaturity < virtualSelectedParentBlueScore
}
