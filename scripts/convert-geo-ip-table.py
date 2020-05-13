#!/usr/bin/env python3
import argparse
from math import log2

import pandas as pd

# by defaults gets geo-ip tables from https://software77.net/geo-ip/

parser = argparse.ArgumentParser(description="")
parser.add_argument("outfile", type=str)
parser.add_argument(
    "--infile_v4",
    type=str,
    default="http://software77.net/geo-ip/?DL=1",  # IpToCountry.csv.gz
)
parser.add_argument(
    "--infile_v6",
    type=str,
    default="http://software77.net/geo-ip/?DL=9",  # IpToCountry.6C.csv.gz
)
args = parser.parse_args()

mapping = {
    # replace ISO2 with country code: "ISO2": score
}
additional = [("127.0.0.0", 24, 0)]


def get_ipv4_rows(filename):
    def convert_ipv4(v):
        r = [0, 0, 0, 0]
        for i in range(4):
            r[i] = str(v % 256)
            v = v // 256
        return ".".join(reversed(r))

    def convert_ipv4_range(v):
        l = log2(v.ip_to - v.ip_from + 1)
        if int(l) != l:
            raise RuntimeError(
                f"Incompatible IP range {convert_ipv4(v.ip_from)}-{convert_ipv4(v.ip_to)}"
            )
        v.ip_from = convert_ipv4(v.ip_from)
        v.cidr_suffix = int(l)
        return v

    d = pd.read_csv(
        filename,
        comment="#",
        names=["ip_from", "ip_to", "registry", "assigned", "iso2", "iso3", "country"],
    )
    d["score"] = d.iso2.map(mapping)
    d.dropna(inplace=True)
    d["score"] = d.score.astype(int)
    d["cidr_suffix"] = 0
    return d.apply(convert_ipv4_range, axis=1, result_type="broadcast").drop(
        columns=["ip_to", "registry", "assigned", "iso2", "iso3", "country"]
    )


def get_ipv6_rows(filename):
    def convert_ipv6_range(v):
        l = v.ip_from.split("/")
        v.ip_from = l[0]
        v.cidr_suffix = l[1]
        return v

    d = pd.read_csv(
        filename, comment="#", names=["ip_from", "iso2", "registry", "assigned"],
    )
    d["score"] = d.iso2.map(mapping)
    d.dropna(inplace=True)
    d["score"] = d.score.astype(int)
    d["cidr_suffix"] = 0
    return d.apply(convert_ipv6_range, axis=1, result_type="broadcast").drop(
        columns=["registry", "assigned", "iso2"]
    )


additionalframe = pd.DataFrame(additional, columns=["ip_from", "cidr_suffix", "score"])
pd.concat(
    (get_ipv4_rows(args.infile_v4), get_ipv6_rows(args.infile_v6), additionalframe)
).to_csv(args.outfile, index=False, columns=["ip_from", "cidr_suffix", "score"])
