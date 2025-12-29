# iptables AI Analyzer with Ollama

`iptables-ai-analyzer` is a tool designed to analyze Linux `iptables` rules using AI models. It provides insights into potential security issues and suggests improvements to your firewall configuration. The tool leverages the Ollama AI model for advanced analysis and generates detailed reports.

## Features

- Collects and analyzes `iptables` rules.
- Summarizes traffic data, including top sources.
- Uses the Ollama AI model to identify security issues and suggest firewall rules.
- Generates JSON reports and candidate scripts for applying suggested rules.

## Requirements

- Rust (for building the project)
- A running instance of the Ollama AI server
- `iptables-save` and `iptables` commands available on the system

## Installation

1. Clone the repository:
   ```sh
   git clone <repository-url>
   cd iptables-ai-analyzer
   ```

2. Build the project:
   ```sh
   cargo build --release
   ```

3. Ensure the `config.toml` file is properly configured (see below).

## Configuration

The tool uses a `config.toml` file for its configuration. Below is an example:

```toml
[general]
log_path = "/var/log/iptables.log"
output_dir = "/tmp/iptables-ai"

[iptables]
iptables_save_cmd = "/sbin/iptables-save"
iptables_list_cmd = "/sbin/iptables"

[ollama]
host = "http://127.0.0.1:11434"
model = "llama3.1:8b"
timeout_secs = 120
```

- **log_path**: Path to the log file for storing logs.
- **output_dir**: Directory where reports and scripts will be saved.
- **iptables_save_cmd**: Command to save `iptables` rules.
- **iptables_list_cmd**: Command to list `iptables` rules.
- **host**: URL of the Ollama AI server.
- **model**: AI model to use for analysis.
- **timeout_secs**: Timeout for requests to the AI server.

## Usage

Run the tool with the following command:

```sh
./target/release/iptables-ai-analyzer --config /path/to/config.toml --mode <mode>
```

- **--config**: Path to the configuration file (default: `/etc/iptables-ai/config.toml`).
- **--mode**: Mode of operation (`report` or `candidate`).

### Modes

- **report**: Generates a JSON report with findings and suggestions.
- **candidate**: Generates a JSON report and a shell script with suggested `iptables` rules.

## Example Output

- **Report**: A JSON file containing traffic summaries, findings, and suggested rules.
- **Candidate Script**: A shell script to apply suggested `iptables` rules.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Contact

For questions or support, please contact [classx@gmail.com](mailto:classx@gmail.com).
```

Let me know if you'd like to make any adjustments!
