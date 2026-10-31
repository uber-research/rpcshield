package reporting

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/uber-research/rpcshield/go/constant"
	"github.com/uber-research/rpcshield/go/grail"
	"github.com/uber-research/rpcshield/go/output"
)

const _defaultReadyToFileJiraTicket = false

// CSV header
var header = []string{
	"id",                             // unique identifier for the report
	"run_timestamp",                  // timestamp when rpcshield was run.
	"source",                         // source generating the report (e.g., go_static, java_dynamic, java_static etc.)
	"repo",                           // repository name (e.g. the name of the analyzed repository)
	"gitsha",                         // git SHA of the commit that the report is generated for
	"inbound_service",                // inbound service name
	"inbound_service_tier",           // inbound service tier
	"inbound_endpoint",               // inbound endpoint canonical name
	"outbound_service",               // outbound service name
	"outbound_service_tier",          // outbound service tier
	"outbound_endpoint",              // outbound endpoint canonical name
	"outbound_has_overcommit",        // whether the outbound service has any environment with overcommit namespace
	"outbound_has_break_before_make", // whether the outbound service has any environment with BURST_STRATEGY_BREAK_BEFORE_MAKE
	"outbound_has_make_before_break", // whether the outbound service has any environment with BURST_STRATEGY_MAKE_BEFORE_BREAK
	"num_paths",                      // number of call paths between the inbound-outbound quadruple
	"path_reports",                   // reports (in JSON format) of all call paths between the inbound-outbound quadruple
	"report_result",                  // final fail-ness result for the inbound-outbound quadruple
	"ready_to_file_jira_ticket",      // whether the report is ready to be filed as a JIRA ticket (used for manual verification)
	"other_info",                     // optional field for any other information that might be useful for debugging
}

// GetCSVHeader returns the CSV header fields.
func GetCSVHeader() []string {
	// Return a copy of the header to prevent modification to the original header
	return slices.Clone(header)
}

// WriteReportsToCSV writes the given reports to a CSV file.
func WriteReportsToCSV(outputDir string, service grail.Service, reports []output.Report, gitSHA, timestamp, source, repoName, tbFileURLTemplate string) (string, int, error) {
	if len(reports) == 0 {
		return "", 0, errors.New("no reports to write")
	}

	// Inject a synthetic row to indicate the successful analysis of the service. The ID would be
	// the synthetic ID, and only the inbound service name is populated.
	csvReports := slices.Clone(reports)
	csvReports = append(csvReports, output.Report{ID: output.SyntheticID, Inbound: output.EndPoint{Service: service}, Status: constant.FailUnknown})

	// Create a CSV file in the output directory with the name `<service>.csv`
	csvFilePath := filepath.Join(outputDir, fmt.Sprintf("%s.csv", service.Name))

	// Open the CSV file
	file, err := os.Create(csvFilePath)
	if err != nil {
		return "", 0, fmt.Errorf("cannot create file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	var rowsSuccessfullyWritten int

	// Write CSV header
	if err := writer.Write(header); err != nil {
		return "", 0, fmt.Errorf("cannot write header: %v", err)
	}
	rowsSuccessfullyWritten++

	var dataErr error

	for _, report := range csvReports {
		// Serialize PathResults to JSON
		pathReportsJSON, err := json.Marshal(report)
		if err != nil {
			dataErr = errors.Join(dataErr, fmt.Errorf("error marshaling PathResult: %v", err))
			continue
		}

		// Prepare HTML file URL on the configured object storage backend
		htmlFileURL := constant.BuildTBFileURL(tbFileURLTemplate, repoName, service.Name, timestamp) + getHTMLFileName(service.Name) + "#" + report.ID

		// Prepare data row
		dataRow := []string{
			report.ID,                   // Column: id
			timestamp,                   // Column: run_timestamp
			source,                      // Column: source
			repoName,                    // Column: repo
			gitSHA,                      // Column: gitsha
			report.Inbound.Service.Name, // Column: inbound_service
			strconv.Itoa(report.Inbound.Service.Tier),                 // Column: inbound_service_tier
			report.Inbound.APIName,                                    // Column: inbound_endpoint
			report.Outbound.Service.Name,                              // Column: outbound_service
			strconv.Itoa(report.Outbound.Service.Tier),                // Column: outbound_service_tier
			report.Outbound.APIName,                                   // Column: outbound_endpoint
			strconv.FormatBool(report.Outbound.Service.HasOvercommit), // Column: outbound_has_overcommit
			report.Outbound.Service.BreakBeforeMakeBurstStrategy,      // Column: outbound_break_before_make_burst_strategy
			report.Outbound.Service.MakeBeforeBreakBurstStrategy,      // Column: outbound_make_before_break_burst_strategy
			strconv.Itoa(report.TotalPaths),                           // Column: num_paths
			string(pathReportsJSON),                                   // Column: path_reports
			string(report.Status),                                     // Column: report_result
			strconv.FormatBool(_defaultReadyToFileJiraTicket),         // Column: ready_to_file_jira_ticket
			htmlFileURL, // Column: other_info
		}

		if len(dataRow) != len(header) {
			dataErr = errors.Join(dataErr, fmt.Errorf("data row length %d does not match header length %d", len(dataRow), len(header)))
			continue
		}

		// Write data row
		if err := writer.Write(dataRow); err != nil {
			dataErr = errors.Join(dataErr, fmt.Errorf("cannot write data row: %v", err))
			continue
		}
		rowsSuccessfullyWritten++
	}

	return csvFilePath, rowsSuccessfullyWritten, dataErr
}
