package observer

import (
	"context"
	"github.com/ledgerwatch/erigon/crypto"
	"github.com/ledgerwatch/erigon/p2p/enode"
	"github.com/ledgerwatch/erigon/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHandshake(t *testing.T) {
	t.Skip("only for dev")

	// grep 'self=enode' the log, and paste it here
	// url := "enode://..."
	url := params.MainnetBootnodes[0]
	node := enode.MustParseV4(url)
	myPrivateKey, _ := crypto.GenerateKey()

	ctx := context.Background()
	hello, err := Handshake(ctx, node.IP(), node.TCP(), node.Pubkey(), myPrivateKey)

	require.Nil(t, err)
	require.NotNil(t, hello)
	assert.Equal(t, uint64(5), hello.Version)
	assert.NotEmpty(t, hello.ClientID)
	assert.Contains(t, hello.ClientID, "erigon")
}