package efficacy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type PayloadLoader struct {
	dataPath string
}

func NewPayloadLoader(dataPath string) *PayloadLoader {
	return &PayloadLoader{dataPath: dataPath}
}

// GetFiles returns a map of test name to absolute file path instead of loading all payloads to RAM.
func (pl *PayloadLoader) GetFiles() (map[string]string, error) {
	files := make(map[string]string)

	err := filepath.Walk(pl.dataPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(path) == ".json" {
			testName := filepath.Base(path)
			testName = testName[:len(testName)-5] // Remove .json
			files[testName] = path
		}

		return nil
	})

	return files, err
}

// StreamFile decodes a JSON file containing a JSON array of Payload structs sequentially.
// It sends parsed payloads into the provided channel and closes the payload count when finished.
func (pl *PayloadLoader) StreamFile(path string, payloadsChan chan<- Payload) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)

	// Read opening bracket '['
	t, err := decoder.Token()
	if err != nil {
		return 0, fmt.Errorf("failed to read opening token: %w", err)
	}
	if delim, ok := t.(json.Delim); !ok || delim != '[' {
		return 0, fmt.Errorf("expected JSON array, got %v", t)
	}

	count := 0
	// While the array contains values
	for decoder.More() {
		var payload Payload
		if err := decoder.Decode(&payload); err != nil {
			return count, fmt.Errorf("failed to decode element %d: %w", count, err)
		}

		payload.Index = count
		payloadsChan <- payload
		count++
	}

	// Read closing bracket ']'
	_, err = decoder.Token()
	if err != nil {
		return count, fmt.Errorf("failed to read closing token: %w", err)
	}

	return count, nil
}
