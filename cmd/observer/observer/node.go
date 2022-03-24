package observer

import (
	"errors"
	"fmt"
	"github.com/ledgerwatch/erigon/cmd/observer/database"
	"github.com/ledgerwatch/erigon/p2p/enode"
	"net/url"
)

func nodeID(node *enode.Node) (database.NodeID, error) {
	if node.Incomplete() {
		return "", errors.New("nodeID not implemented for incomplete nodes")
	}
	nodeURL, err := url.Parse(node.URLv4())
	if err != nil {
		return "", fmt.Errorf("failed to parse node URL: %w", err)
	}
	id := nodeURL.User.Username()
	return database.NodeID(id), nil
}
