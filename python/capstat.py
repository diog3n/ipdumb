import csv
import sys


# Simple class that contains stats of the source ip address
class IPData:
    def __init__(self, in_packet_count: int = 0, in_bytes: int = 0,
                 out_packet_count: int = 0, out_bytes: int = 0):
        self._in_packet_count = in_packet_count
        self._in_bytes = in_bytes
        self._out_packet_count = out_packet_count
        self._out_bytes = out_bytes


# column names in csv file:
# source_ip,dest_ip,source_port,dest_port,packet_count,bytes

# turns table from the csv file into a table with columns:
# source_ip, in_packet_count, in_bytes, out_packet_count, out_packets
def read_ip_stats(filename: str):

    # stats are going to be stored in a table
    # of ip_address -> {IPData} pairs
    ip_data_table: dict[str, IPData] = {}

    # opening a file for reading
    in_file = open(filename, mode='r')
    table = csv.DictReader(in_file)

    for line in table:

        # if there is no ip address key in a table then add it
        # IPData will be initialized with zero values
        if line["source_ip"] not in ip_data_table:
            ip_data_table.update({line["source_ip"]: IPData()})

        ip_data_table[
                line["source_ip"]
            ]._out_packet_count += int(line["packet_count"])

        ip_data_table[line["source_ip"]]._out_bytes += int(line["bytes"])

        # again, if there is no ip address key, add it
        if line["dest_ip"] not in ip_data_table:
            ip_data_table.update({line["dest_ip"]: IPData()})

        ip_data_table[
                line["dest_ip"]
            ]._in_packet_count += int(line["packet_count"])

        ip_data_table[line["dest_ip"]]._in_bytes += int(line["bytes"])

    in_file.close()

    return ip_data_table


# print header of the table in output csv file
def print_header(file=None):
    print("source_ip,in_packet_count,in_bytes,"
          + "out_packet_count,out_packets", file=file)


# print ip_data_table table into the file or terminal
def print_ip_data_table(ip_data_table: dict[str, IPData], file=None):
    is_first = True

    print_header(file)

    for ip_addr in ip_data_table:
        if not is_first:
            print("", file=file)  # add a newline at the end if not first

        is_first = True
        print(f"{ip_addr},{ip_data_table[ip_addr]._in_packet_count},"
              + f"{ip_data_table[ip_addr]._in_bytes},"
              + f"{ip_data_table[ip_addr]._out_packet_count},"
              + f"{ip_data_table[ip_addr]._out_bytes}",
              end=None, file=file)


# print a usage reminder for users
def print_usage():
    print("Usage:\n"
          + "    python3 capstat.py [input_file.csv] [output_file.csv]\n"
          + "or\n"
          + "    python3 capstat.py [input_file.csv]")


if len(sys.argv) < 2 or len(sys.argv) > 3:
    print_usage()
    exit(0)

ip_stats = read_ip_stats(sys.argv[1])

if len(sys.argv) > 2:
    file_out = open(sys.argv[2], mode='w')
    print_ip_data_table(ip_stats, file_out)
    exit(0)

print_ip_data_table(ip_stats)
