# ML-NIDS command line tool

## by Josiah Wu, Henry Ng and Terry Wang

The application can extract NetFlow v3 features from a pcap file or live interface, whose flows are then classified via AWS Lambda API.

Note: this project is formerly named AI_NIDS, hence most of the configuration files are under this name.

## Example Usage:

```
    python ai_nids_cli.py -i capture.pcap
    python ai_nids_cli.py -i capture.pcap -o flows.csv
    sudo python ai_nids_cli.py -i eth0 --api-url NIDS_API_URL --api-key NIDS_API_KEY
```

Please contact us for the NIDS_API_URL and the NIDS_API_KEY.

## Other commands:

### Classify a pcap (URL/key as args)

```
python ai_nids_cli.py -i capture.pcap --api-url NIDS_API_URL --api-key NIDS_API_KEY
```

### Classify and also save the extracted CSV

```
python ai_nids_cli.py -i capture.pcap -o flows.csv --api-url NIDS_API_URL --api-key NIDS_API_KEY
```

### Just extract flows without Benign vs Malicious classification

```
python ai_nids_cli.py -i capture.pcap -o flows.csv --no-classify
```

## Recommended: Set API key and URL as environment variables before usage

```
$env:NIDS_API_URL="..."; code .
$env:NIDS_API_KEY="..."; code .
```
