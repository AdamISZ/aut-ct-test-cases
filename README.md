# Test cases and auditing of operation of Pedersen-DLEQ proofs for the "Anonymous Usage Tokens with Curve Trees" project.
 
Should be installable with `pip install .`. Note that there is currently only one external dependency, namely [this one](https://pypi.org/project/python-bitcointx/), which we use for manipulation of secp256k1 points in Python.

To create test cases, run `src/peddleq.py create`. See that source file for other possible arguments for auditing specific cases.

Note that a big chunk of the complexity is not so much the processing of the sigma protocol, but the creation of the hash challenge. In the root project, [Merlin](https://merlin.cool/index.html) is used to create transcripts, which in turn uses [STROBE](https://strobe.sourceforge.io/), which has a very specific, complex protocol to create a PRF output from labels and transcript elements. See detailed commentary in `peddleq.py`.
