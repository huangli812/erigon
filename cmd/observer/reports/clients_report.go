package reports

import (
	"context"
	"fmt"
	"github.com/ledgerwatch/erigon/cmd/observer/database"
	"github.com/ledgerwatch/erigon/cmd/observer/observer"
	"strings"
)

type ClientsReportEntry struct {
	Name  string
	Count uint
}

type ClientsReport struct {
	Clients []ClientsReportEntry
}

func CreateClientsReport(ctx context.Context, db database.DB, limit uint, maxPingTries uint) (*ClientsReport, error) {
	groups := make(map[string]uint)
	unknownCount := uint(0)
	enumFunc := func(clientID *string) {
		if clientID != nil {
			if observer.IsClientIDBlacklisted(*clientID) {
				return
			}
			clientName := observer.NameFromClientID(*clientID)
			groups[clientName]++
		} else {
			unknownCount++
		}
	}
	if err := db.EnumerateClientIDs(ctx, maxPingTries, enumFunc); err != nil {
		return nil, err
	}

	totalCount := sumMapValues(groups)

	report := ClientsReport{}

	for i := uint(0); i < limit; i++ {
		clientName, count := takeMapMaxValue(groups)
		if count == 0 {
			break
		}

		client := ClientsReportEntry{
			clientName,
			count,
		}
		report.Clients = append(report.Clients, client)
	}

	othersCount := sumMapValues(groups)

	report.Clients = append(report.Clients,
		ClientsReportEntry{"...", othersCount},
		ClientsReportEntry{"total", totalCount},
		ClientsReportEntry{"unknown", unknownCount})

	return &report, nil
}

func (report *ClientsReport) String() string {
	var builder strings.Builder
	builder.WriteString("clients:")
	builder.WriteRune('\n')
	for _, client := range report.Clients {
		builder.WriteString(fmt.Sprintf("%6d %s", client.Count, client.Name))
		builder.WriteRune('\n')
	}
	return builder.String()
}

func takeMapMaxValue(m map[string]uint) (string, uint) {
	maxKey := ""
	maxValue := uint(0)

	for k, v := range m {
		if v > maxValue {
			maxKey = k
			maxValue = v
		}
	}

	delete(m, maxKey)
	return maxKey, maxValue
}

func sumMapValues(m map[string]uint) uint {
	sum := uint(0)
	for _, v := range m {
		sum += v
	}
	return sum
}
