package reports

import (
	"context"
	"fmt"
	"github.com/ledgerwatch/erigon/cmd/observer/database"
	"strings"
)

type StatusReport struct {
	TotalCount      uint
	DistinctIPCount uint
}

func CreateStatusReport(ctx context.Context, db database.DB, maxPingTries uint) (*StatusReport, error) {
	totalCount, err := db.CountNodes(ctx, maxPingTries)
	if err != nil {
		return nil, err
	}

	distinctIPCount, err := db.CountIPs(ctx, maxPingTries)
	if err != nil {
		return nil, err
	}

	report := StatusReport{
		totalCount,
		distinctIPCount,
	}
	return &report, nil
}

func (report *StatusReport) String() string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("total: %d", report.TotalCount))
	builder.WriteRune('\n')
	builder.WriteString(fmt.Sprintf("distinct IPs: %d", report.DistinctIPCount))
	builder.WriteRune('\n')
	return builder.String()
}
