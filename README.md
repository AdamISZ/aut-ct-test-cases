This repository contains useful tools for testing and data set generation for [AUTCT](https://github.com/AdamISZ/aut-ct).
 
## Generation of keyset files for the AUT-CT project (and proof of assets)
Should be installable with `pip install .`.

Note that there is currently only one external dependency, namely [this one](https://pypi.org/project/python-bitcointx/), which we use for manipulation of secp256k1 points in Python.

To create keysets from sqlite database files, first, see [here](https://github.com/AdamISZ/aut-ct/blob/master/docs/utxo-keysets.md) for the overall process, but in particular, use:

```
cd src
python filter-utxos.py 500000 \
input-database-file.sqlite \
your-keyset-name.pks audit
```

... to generate a keyset file for proof-of-assets (note the `.pks` file extension, that's required). If you remove the last argument `audit`, then use `*.aks` instead for the output filename, and it will generate a keyset for the aut-ct (anonymous usage token) use-case.

## Test case generation for sub protocol components

To create test cases for Ped-DLEQ, run `src/peddleq.py create`. See that source file for other possible arguments for auditing specific cases.

Note that a big chunk of the complexity is not so much the processing of the sigma protocol, but the creation of the hash challenge. In the root project, [Merlin](https://merlin.cool/index.html) is used to create transcripts, which in turn uses [STROBE](https://strobe.sourceforge.io/), which has a very specific, complex protocol to create a PRF output from labels and transcript elements. See detailed commentary in `peddleq.py`.
