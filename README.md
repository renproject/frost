#Frost

Implementation of FROST multiparty signatures, in go. Paper can be accessed online [here](https://eprint.iacr.org/2020/852.pdf).

The implementation currently only supports using a signature aggregator (see paper for details).
The API is component style; the package exposes message and state types, and the functions handle incoming messages and possibly return a message that needs to be sent, or a signature if signing is complete, as well as potentially returning an error in the case of malicious behaviour or otherwise.
This means that it is the responsibility of the user of `frost` to handle sending and receiving messages over the network.

This repository is a work in progress. The following is a list of things that still need to be done.

- Make support for BIP340 a configurable option.
- Add more tests.
- Add more documentation.
