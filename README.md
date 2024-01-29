# ipdumb
Is a simple .pcap analyzer.

## Usage:

```
ipdumb [dev|file] [device_name|filename.pcap] output_file.csv
```
## Dependencies
### Debian
- libpcap-dev
```bash
sudo apt install libpcap-dev
```

### Fedora
- libpcap-devel
```bash
sudo dnf install libpcap-devel
```

## Building
```bash
mkdir build && cd build
cmake .. && cmake --build .
``` 

# capstat
Is a simple IP stat processor.

It takes ipdumb output .csv file and transforms it into its own .csv table with data about every ip adress and amount of packets and bytes sent and received.

## Dependencies
Python 3.9+