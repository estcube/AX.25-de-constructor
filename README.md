# AX.25 (De)constructor

This repository contains Python code to create or disassemble AX.25 packets.
There's no TNC communication, digipeater or any other additional logic added.
You just specify what kind of AX.25 packet you want and out comes the appropriate encoded packet as bytearray that you can manipulate as you wish.
For decoding, it just splits the AX.25 bytestream into separate fields and offers the functionality to decode the dst and src addresses into human readable form.

You can find usage example in the [ax25_example.py](ax25_example.py) file.
