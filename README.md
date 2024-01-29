# ipdumb
Is a simple TCP/UDP traffic analyzer.

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
