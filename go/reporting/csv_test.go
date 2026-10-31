package reporting

import (
	"encoding/csv"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/uber-research/rpcshield/go/constant"
	"github.com/uber-research/rpcshield/go/grail"
	"github.com/uber-research/rpcshield/go/output"
)

func TestGetCSVHeader(t *testing.T) {
	res := GetCSVHeader()
	require.Equal(t, res, header)
}

func TestCSV_Write(t *testing.T) {
	testCases := []struct {
		name             string
		service          string
		reports          []output.Report
		gitSHA           string
		expectedRows     int
		expectError      bool
		checkCSVContent  bool
		expectedCSVLines int // including header
	}{
		{
			name:             "Empty reports",
			service:          "testService",
			reports:          []output.Report{},
			gitSHA:           "testSHA",
			expectedRows:     0,
			expectError:      true,
			checkCSVContent:  false,
			expectedCSVLines: 0, // nothing to write
		},
		{
			name:    "Valid report FailClose",
			service: "InboundService",
			reports: []output.Report{
				{
					Inbound: output.EndPoint{
						Service: grail.Service{
							Name: "InboundService",
							Tier: 1,
						},
						APIName: "InboundService__InboundFunc",
					},
					Outbound: output.EndPoint{
						Service: grail.Service{
							Name: "OutboundService",
							Tier: 5,
						},
						APIName: "OutboundService__OutboundFunc",
					},
					PathResults: []output.PathResult{
						{
							Edges: []*output.EdgeWrapper{
								{
									Caller:          "OutboundFunc",
									Callee:          "foo",
									SourceGraphLink: "sourcegraph link",
									AnalyzerOutput: output.AnalyzerOutput{
										Status: constant.FailClose,
									},
								},
								{
									Caller:          "foo",
									Callee:          "InboundFunc",
									SourceGraphLink: "sourcegraph link",
									AnalyzerOutput: output.AnalyzerOutput{
										Status: constant.FailClose,
									},
								},
							},
							Status: constant.FailClose,
						},
					},
					Status: constant.FailClose,
				},
			},
			gitSHA:           "testSHA",
			expectedRows:     3,
			expectError:      false,
			checkCSVContent:  true,
			expectedCSVLines: 3, // header + one data row + synthetic row
		},
		{
			name:    "Valid report multiple endpoints",
			service: "InboundService",
			reports: []output.Report{
				{
					Inbound: output.EndPoint{
						Service: grail.Service{
							Name: "InboundService",
							Tier: 1,
						},
						APIName: "InboundService__InboundFunc",
					},
					Outbound: output.EndPoint{
						Service: grail.Service{
							Name: "OutboundService",
							Tier: 5,
						},
						APIName: "OutboundService__OutboundFunc",
					},
					PathResults: []output.PathResult{
						{
							Edges: []*output.EdgeWrapper{
								{
									Caller:          "OutboundFunc",
									Callee:          "foo",
									SourceGraphLink: "sourcegraph link",
									AnalyzerOutput: output.AnalyzerOutput{
										Status: constant.FailClose,
									},
								},
								{
									Caller:          "foo",
									Callee:          "InboundFunc",
									SourceGraphLink: "sourcegraph link",
									AnalyzerOutput: output.AnalyzerOutput{
										Status: constant.FailClose,
									},
								},
							},
							Status: constant.FailClose,
						},
					},
					Status: constant.FailClose,
				},
				{
					Inbound: output.EndPoint{
						Service: grail.Service{
							Name: "InboundService",
							Tier: 1,
						},
						APIName: "InboundService__InboundFunc",
					},
					Outbound: output.EndPoint{
						Service: grail.Service{
							Name: "OutboundService",
							Tier: 5,
						},
						APIName: "OutboundService__OutboundFunc",
					},
					PathResults: []output.PathResult{
						{
							Edges: []*output.EdgeWrapper{
								{
									Caller:          "OutboundFunc",
									Callee:          "bar",
									SourceGraphLink: "sourcegraph link",
									AnalyzerOutput: output.AnalyzerOutput{
										Status: constant.FailClose,
									},
								},
								{
									Caller:          "bar",
									Callee:          "InboundFunc",
									SourceGraphLink: "sourcegraph link",
									AnalyzerOutput: output.AnalyzerOutput{
										Status: constant.FailOpen,
									},
								},
							},
							Status: constant.FailOpen,
						},
					},
					Status: constant.FailClose,
				},
			},
			gitSHA:           "testSHA",
			expectedRows:     4,
			expectError:      false,
			checkCSVContent:  true,
			expectedCSVLines: 4, // header + two data rows + synthetic row
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			service := grail.Service{Name: tc.service, Tier: -1}
			filename, rowsWritten, err := WriteReportsToCSV(t.TempDir(), service, tc.reports, tc.gitSHA, time.Now().UTC().Format(time.RFC3339), constant.SourceForCSV, "example-repo", "")

			// Check for expected errors
			if tc.expectError {
				require.Errorf(t, err, "Expected error, but got nil")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)
			}

			// Check the number of rows written
			require.Equalf(t, tc.expectedRows, rowsWritten, "Expected %d rows written, got %d", tc.expectedRows, rowsWritten)

			// Check CSV
			if tc.checkCSVContent {
				// Read the CSV file
				content, err := os.ReadFile(filename)
				require.NoErrorf(t, err, "Failed to read CSV file: %v", err)
				// Parse the CSV content
				reader := csv.NewReader(strings.NewReader(string(content)))
				records, err2 := reader.ReadAll()
				require.NoErrorf(t, err2, "Failed to parse CSV file: %v", err2)

				// Check the number of lines in the CSV
				require.Equalf(t, tc.expectedCSVLines, len(records), "Expected %d lines in CSV file, got %d", tc.expectedCSVLines, len(records))
			}
		})
	}
}
