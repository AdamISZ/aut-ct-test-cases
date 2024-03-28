#! /usr/bin/env python
"""
To prepare data for input to this tool:

1. Query the bitcoind RPC:

```
bitcoin-cli dumptxoutset "yourabsolutepathfilename"
```

(which can take a long while; it's a full utxo snapshot).

2. Run this tool:

https://github.com/theStack/utxo_dump_tools/blob/master/utxo_to_sqlite/utxo_to_sqlite.go

.. with appropriate input (the above) and output file names. The output file can then be used as input to this querying tool.

Note also that the output file produced here is in the format taken by https://github.com/AdamISZ/aut-ct for usage tokens from a pubkey set.

TODO:
There are pros and cons to allowing repeated pubkeys here, depending on the usage scenario. For now, duplicates are allowed, so a post-processing step like list(set(x)) may be needed.
"""

import sys
from sqlite3 import connect, Cursor, Row

def setup_db(fn):
    source = connect(fn)
    return source.cursor()

def select_the_scripts(db, low_filter):
    spks = db.execute(
        "SELECT scriptpubkey FROM 'utxos' WHERE value >= ? \
        AND scriptpubkey LIKE '5120%';", (low_filter,)).fetchall()
    return [x[0] for x in spks]

if __name__ == "__main__":
    print("Using sat value filter: {}, input file: {}\
    , and output file: {}".format(*sys.argv[1:]))
    c = setup_db(sys.argv[2])
    spks = select_the_scripts(c, sys.argv[1])
    print("Retrieved this many taproot pubkeys: ", len(spks))
    with open(sys.argv[3], "wb") as f:
        f.write((" ".join([x[4:] for x in spks])).encode())
