from ax25 import *

"""
Create a UI frame with a custom payload
"""
dst_ssid = 0
dst_callsign = "ES5E"

src_ssid = 0
src_callsign = "ES5EC"

payload = bytearray.fromhex("CA FE CA FE CA FE")

ax25_conf = {"use_modulo8": True, "set_pf_bit": False, "pid_field": AX25_PID_Fields.AX25_PID_NO_LAYER3}
created_packet = ax25_create_frame(dst_callsign, dst_ssid, src_callsign, src_ssid, AX25_Ctrl_Fields.AX25_CTRL_UI,
    payload, **ax25_conf)

for byte in created_packet:
    print('{:02x}'.format(byte).upper(), end="")
print()

disassembled_frame = ax25_disassemble_raw_frame(created_packet)
print(disassembled_frame)