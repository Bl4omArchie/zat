import argparse
import sys



def main():
    parser = argparse.ArgumentParser(
        prog="zat",
        description="read zeek log"
    )

    parser.add_argument('-zl', 'zeek_log', type=str, help='Specify the zeek log input file')
    parser.add_argument('-df', 'dataframe', type=str, choices=["pandas", "polars", "dask", "spark"], help='Specify the dataframe to convert the log with')
    parser.add_argument('parquet_file', type=str, help='Specify the parquet file to write out')
    parser.add_argument('-t', '--tail', action='store_true', help='Turn on log tailing')
    parser.add_argument('-t', action='store_true', default=False, help='Sets the program to tail a live Zeek log')
    parser.add_argument('-s', action='store_true', default=False, help='Only print the summary of the findings.')
    parser.add_argument('--server', type=str, default='localhost:9092',
                        help='Specify the Kafka Server (default: localhost:9092)')
    parser.add_argument('--topics', type=lambda s: s.split(','), default='all',
                        help='Specify the Kafka Topics (e.g. dns   or   dns, http, blah   (defaults to all)')
    parser.add_argument('dns_log', help='Specify the zeek DNS log')
    parser.add_argument('whitelist', help='Specify the DNS whiteliist')
    parser.add_argument('-r', '--rule-index', type=str, required=True, help='Specify the yara rule index file (e.g. /full/path/to/yara/rules/index.yar)')
    parser.add_argument('-e', '--extract-dir', type=str, required=True, help='Specify the Zeek extract_files directory (e.g. /full/path/to/zeek/extract_files)')

    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)



if __name__ == "__main__":
    main()
