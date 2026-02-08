# Report Format

The scanner outputs a report with the following fields:

- `target`: Absolute path to the scanned file or folder
- `verdict`: `clean`, `review`, or `danger`
- `summary`: Counts by severity (`high`, `medium`, `low`)
- `findings`: List of findings
- `skipped`: Files skipped due to size or read errors

## Finding schema

Each finding has:

- `severity`: `high`, `medium`, or `low`
- `category`: `network`, `exec`, `destructive`, `obfuscation`, `secrets`, `hidden_content`, `binary`
- `path`: File path
- `line`: Line number if available, otherwise `null`
- `snippet`: The matched text snippet (short)
