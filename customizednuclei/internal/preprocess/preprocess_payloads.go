package preprocess

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var replaceRegex = regexp.MustCompile(`replace\("\{\{([^}]+)\}\}",\s*"([^"]+)",\s*"([^"]+)"\)`)

// processPayloadBlocks looks for custom OWASP "preprocessors" blocks inside "http" requests,
// evaluates their rules to generate new wordlists dynamically, and modifies
// the template to point to the newly generated temporary files.
// It also strips the "preprocessors" block so Nuclei SDK loads the template without errors.
func processPayloadBlocks(doc map[string]interface{}) error {
	httpBlocks, ok := doc["http"].([]interface{})
	if !ok {
		return nil
	}

	varsMap, _ := doc["variables"].(map[string]interface{})

	for _, blockItem := range httpBlocks {
		block, ok := blockItem.(map[string]interface{})
		if !ok {
			continue
		}

		// --- PHASE 1: EXPAND {{v}} IN PAYLOADS ---
		payloadsMap, hasPayloads := block["payloads"].(map[string]interface{})
		if hasPayloads && varsMap != nil {
			for k, v := range payloadsMap {
				switch sv := v.(type) {
				case string:
					payloadsMap[k] = expandVarString(sv, varsMap)
				case []interface{}:
					var allExpanded []interface{}
					var isFile bool

					for _, elem := range sv {
						if strElem, ok := elem.(string); ok {
							exp := expandVarString(strElem, varsMap)
							allExpanded = append(allExpanded, exp)
							// If any element checks out as a real file path, we tag this payload chunk as a file list.
							if _, err := os.Stat(exp); err == nil {
								isFile = true
							}
						} else {
							allExpanded = append(allExpanded, elem)
						}
					}
					
					if isFile {
						if len(allExpanded) == 1 {
							if str, ok := allExpanded[0].(string); ok {
								payloadsMap[k] = str
							}
						} else {
							// For multiple files, let Phase 2 or the fallback block merge them
							payloadsMap[k] = allExpanded
						}
					} else {
						// Ensure variables inside literal strings are still expanded!
						payloadsMap[k] = allExpanded
					}
				}
			}
		}

		// --- PHASE 2: EVALUATE CUSTOM PREPROCESSORS ---
		preprocessorsVal, exists := block["preprocessors"]
		if !exists {
			// Even if there are no preprocessors, if Phase 1 left a []interface{} that contains files,
			// merge them into a single string file so Nuclei's loader works!
			for k, v := range payloadsMap {
				if list, ok := v.([]interface{}); ok {
					var strFiles []string
					hasFile := false
					for _, elem := range list {
						if str, ok := elem.(string); ok {
							strFiles = append(strFiles, str)
							if _, err := os.Stat(str); err == nil {
								hasFile = true
							}
						}
					}
					if hasFile {
						if mergedFile, err := mergePayloadFiles(strFiles); err == nil {
							payloadsMap[k] = mergedFile
						}
					}
				}
			}
			continue
		}

		preprocessorsList, ok := preprocessorsVal.([]interface{})
		if !ok {
			delete(block, "preprocessors")
			continue
		}

		for _, pItem := range preprocessorsList {
			pMap, ok := pItem.(map[string]interface{})
			if !ok {
				continue
			}

			if typeVal, ok := pMap["type"].(string); !ok || typeVal != "template" {
				continue
			}

			generatorList, ok := pMap["generator"].([]interface{})
			if !ok {
				continue
			}

			type ReplaceRule struct {
				Search  string
				Replace string
			}
			rulesByVar := make(map[string][]ReplaceRule)

			for _, gItem := range generatorList {
				gStr, ok := gItem.(string)
				if !ok {
					continue
				}
				matches := replaceRegex.FindStringSubmatch(gStr)
				if len(matches) == 4 {
					varName := matches[1]
					search := matches[2]
					replace := matches[3]
					rulesByVar[varName] = append(rulesByVar[varName], ReplaceRule{
						Search:  search,
						Replace: replace,
					})
				}
			}

			if !hasPayloads {
				continue
			}

			for varName, rules := range rulesByVar {
				var sourceFiles []string

				val := payloadsMap[varName]
				switch v := val.(type) {
				case string:
					sourceFiles = append(sourceFiles, v)
				case []interface{}:
					for _, item := range v {
						if strItem, ok := item.(string); ok {
							sourceFiles = append(sourceFiles, strItem)
						}
					}
				}

				if len(sourceFiles) == 0 {
					continue
				}

				tmpFile, err := os.CreateTemp("", "nuclei-waf-payloads-*.txt")
				if err != nil {
					return fmt.Errorf("create payload temp file: %w", err)
				}

				writer := bufio.NewWriter(tmpFile)
				linesWritten := 0

				for _, sourceFile := range sourceFiles {
					f, err := os.Open(sourceFile)
					if err != nil {
						// Don't warn for literal payloads that masquerade as sourceFiles in schema mismatches
						continue
					}

					scanner := bufio.NewScanner(f)
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if line == "" {
							continue
						}

						for _, rule := range rules {
							result := strings.ReplaceAll(line, rule.Search, rule.Replace)
							if result != line || rule.Search == "{{"+varName+"}}" {
								writer.WriteString(result)
								writer.WriteString("\n")
								linesWritten++
							}
						}
					}
					f.Close()
				}
				writer.Flush()
				tmpFilePath, _ := filepath.Abs(tmpFile.Name())
				tmpFile.Close()

				// Only overwrite the payload key if we actually generated real lines from existing files
				if linesWritten > 0 {
					payloadsMap[varName] = tmpFilePath
				} else {
					os.Remove(tmpFilePath)
				}
			}
		}

		delete(block, "preprocessors")
	}

	return nil
}

func mergePayloadFiles(files []string) (string, error) {
	tmpFile, err := os.CreateTemp("", "nuclei-waf-merged-payloads-*.txt")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	writer := bufio.NewWriter(tmpFile)
	for _, sourceFile := range files {
		f, err := os.Open(sourceFile)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			writer.WriteString(scanner.Text() + "\n")
		}
		f.Close()
	}
	writer.Flush()
	return filepath.Abs(tmpFile.Name())
}

var varRegex = regexp.MustCompile(`\{\{([a-zA-Z0-9_-]+)\}\}`)

func expandVarString(s string, varsMap map[string]interface{}) string {
	return varRegex.ReplaceAllStringFunc(s, func(match string) string {
		key := match[2 : len(match)-2] // strip {{ and }}
		if val, exists := varsMap[key]; exists {
			if strVal, ok := val.(string); ok {
				return strVal
			}
		}
		return match
	})
}
