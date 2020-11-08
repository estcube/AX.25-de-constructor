import crcmod
from enum import Enum, auto, unique

@unique
class AX25_Ctrl_Fields(Enum):
    """ Information Command Frame Control Fields """
    AX25_CTRL_INFO  = 0x00  # Information
    """ Supervisory Frame Control Field """
    AX25_CTRL_RR    = 0x01  # Receive Ready
    AX25_CTRL_RNR   = 0x05  # Receive Not Ready
    AX25_CTRL_REJ   = 0x09  # Reject
    AX25_CTRL_SREJ  = 0x0D  # Selective Reject
    """ Unnumbered Frame Control Fields """
    AX25_CTRL_SABME = 0x6F  # Set Async Balanced Mode (Extended)
    AX25_CTRL_SABM  = 0x2F  # Set Async Balanced Mode
    AX25_CTRL_DISC  = 0x43  # Disconnect
    AX25_CTRL_DM    = 0x0F  # Disconnect Mode
    AX25_CTRL_UA    = 0x63  # Unnumbered Acknowledge
    AX25_CTRL_FRMR  = 0x87  # Frame Reject
    AX25_CTRL_UI    = 0x03  # Unnumbered Information
    AX25_CTRL_XID   = 0xAF  # Exchange Identification
    AX25_CTRL_TEST  = 0xE3  # TEST

@unique
class AX25_Ctrl_Groups(set, Enum):
    INFORMATION = {AX25_Ctrl_Fields.AX25_CTRL_INFO}
    SUPERVISORY = {AX25_Ctrl_Fields.AX25_CTRL_RR, AX25_Ctrl_Fields.AX25_CTRL_RNR, AX25_Ctrl_Fields.AX25_CTRL_REJ,
                    AX25_Ctrl_Fields.AX25_CTRL_SREJ}
    UNNUMBERED  = {AX25_Ctrl_Fields.AX25_CTRL_SABME, AX25_Ctrl_Fields.AX25_CTRL_SABM, AX25_Ctrl_Fields.AX25_CTRL_DISC,
                    AX25_Ctrl_Fields.AX25_CTRL_DM, AX25_Ctrl_Fields.AX25_CTRL_UA, AX25_Ctrl_Fields.AX25_CTRL_FRMR,
                    AX25_Ctrl_Fields.AX25_CTRL_UI, AX25_Ctrl_Fields.AX25_CTRL_XID, AX25_Ctrl_Fields.AX25_CTRL_TEST}
    INFO_FIELD  = {AX25_Ctrl_Fields.AX25_CTRL_INFO, AX25_Ctrl_Fields.AX25_CTRL_UI, AX25_Ctrl_Fields.AX25_CTRL_XID,
                    AX25_Ctrl_Fields.AX25_CTRL_TEST, AX25_Ctrl_Fields.AX25_CTRL_FRMR}
    PID_FIELD   = {AX25_Ctrl_Fields.AX25_CTRL_INFO, AX25_Ctrl_Fields.AX25_CTRL_UI}

@unique
class AX25_PID_Fields(Enum):
    """
    The Protocol Identifier (PID) field appears in information frames (I and UI) only.
    It identifies which kind ofLayer 3 protocol, if any, is in use
    """
    AX25_PID_LAYER3_IMPLEMENTED1    = 0x10  # AX.25 layer 3 implemented
    AX25_PID_LAYER3_IMPLEMENTED2    = 0x20  # AX.25 layer 3 implemented
    AX25_PID_PLP                    = 0x01  # ISO 8208/CCiTT X.25 PLP
    AX25_PID_TCPIP_COMPRESSED       = 0x06  # Compressed TCP/IP packet. Van Jacobson (RFC 1144)
    AX25_PID_TCPIP_UNCOMPRESSED     = 0x07  # Uncompressed TCP/IP packet. Van Jacobson (RFC 1144)
    AX25_PID_TCPIP_SEG_FRAG         = 0x08  # Segmentation fragment
    AX25_PID_TEXNET                 = 0xC3  # TEXNET datagram protocol
    AX25_PID_LINK_QUALITY           = 0xC4  # Link Quality Protocol
    AX25_PID_APPLETALK              = 0xCA  # Appletalk
    AX25_PID_APPLETALK_ARP          = 0xCB  # Appletalk ARP
    AX25_PID_ARPA_INET              = 0xCC  # ARPA Internet Protocol
    AX25_PID_ARPA_ADDR              = 0xCD  # ARPA Address resolution
    AX25_PID_FLEXNET                = 0xCE  # FlexNet
    AX25_PID_NETROM                 = 0xCF  # Net/ROM
    AX25_PID_NO_LAYER3              = 0xF0  # No layer 3 protocol implemented
    AX25_PID_ESC_CHAR               = 0xFF  # Escape character. Next octet contains more Level 3 protocol

def ax25_crc_16_x25(packet: bytearray):
    """
    AX.25 uses CRC-16/X.25
    Polynomial: 0x1021
    Initial Value: 0xFFFF
    Input and Result are both reflected.
    Final XOR Value: 0xFFFF

    Parameters:
    packet: The AX.25 fields as a bytearray i.e. the bytes between the AX.25 start flag (0x7E) and the checksum field.

    Returns:
    bytearray: CRC16 of the input bytearray using the CRC-16/X.25 standard.
    """
    # Check crcmod documentation if you want to know why the intial values are given like this
    crc_fun = crcmod.mkCrcFun(0x11021, initCrc=0x0, rev=True, xorOut=0xFFFF)

    return crc_fun(packet).to_bytes(2, byteorder='little')


def ax25_encode_pid_field(ctrl_type: AX25_Ctrl_Fields, pid_field: AX25_PID_Fields) -> bytes:
    """
    This function takes the input configuration and outputs the correct PID field.
    The Protocol Identifier (PID) field appears in information frames (I and UI) only.

    Parameters:
    ctrl_type:  The type of control field the frame will have. PID field is valid only frames with INFO and UI ctrl
                fields.
    pid_field:  The wished PID field value in human readable form using an enum.

    Returns:
    bytes: bytes object that contains the created pid field
    """
    if ctrl_type not in AX25_Ctrl_Groups.PID_FIELD:
        raise ValueError("The Protocol Identifier (PID) field appears in information frames (I and UI) only. Given " \
            "ctrl type was %s." % (ctrl_type) )

    return pid_field.value.to_bytes(1, byteorder='big')

def ax25_encode_control_field(ctrl_type: AX25_Ctrl_Fields, **ax25_config) -> bytes:
    """
    This function takes the input configuration and outputs a correct control field(s).
    Depending on the configuration given, it looks for the right keywords from the **kwargs dictionary.

    Parameters:
    ctrl_type:         The type of control field to create, different frame formats have different ctrl field options.
    **ax25_config:
        use_modulo8: (bool) If modulo 8 operation is in effect (the default), an I frame is assigned a sequential number
                            from 0 to 7. If modulo 128 operation is in effect, an I frame is assigned a sequential
                            number between 0 and 127.
        set_pf_bit: (bool) Final The P/F bit is used in all types of frames to control frame flow. When not used, the
                           P/F bit is set to “0”.
        rx_seq_nr: (int) the send sequence number.
        tx_seq_nr: (int) the receive sequence number.
        use_modulo128: (bool) The control field can be one or two octets long and may use sequence numbers to maintain
                       link integrity. These sequence numbers may be three-bit (modulo 8) or seven-bit (modulo 128)
                       integers.

    Returns:
    bytes: bytes object that contains the created ctrl field(s)
    """
    encoded_ctrl_field = 0
    if ax25_config["use_modulo8"]:
        if ctrl_type in AX25_Ctrl_Groups.UNNUMBERED:
            encoded_ctrl_field = int(ax25_config["set_pf_bit"]) << 4 | ctrl_type.value

        elif ctrl_type in AX25_Ctrl_Groups.SUPERVISORY:
            if not (-1 < ax25_config["rx_seq_nr"] < 7):
                raise ValueError("Sequence numbers must be from 0 to 7 when using modulo8. Given rx sequence was %i."
                        % (ax25_config["rx_seq_nr"]))
            encoded_ctrl_field = ax25_config["rx_seq_nr"] << 5 | int(ax25_config["set_pf_bit"]) << 4 | \
                    ctrl_type.value

        elif ctrl_type in AX25_Ctrl_Groups.INFORMATION:
            if not (-1 < ax25_config["rx_seq_nr"] < 7) and not (-1 < ax25_config["tx_seq_nr"] < 7):
                raise ValueError("Sequence numbers must be from 0 to 7 when using modulo8. Given rx sequence was %i and"
                        " given tx sequence was %i" % (ax25_config["rx_seq_nr"], ax25_config["tx_seq_nr"]))
            encoded_ctrl_field = ax25_config["rx_seq_nr"] << 5 | int(ax25_config["set_pf_bit"]) << 4 | \
                    ax25_config["rx_seq_nr"] << 1 | ctrl_type.value

        else:
            raise ValueError("The given frame control field of %s is not supported by AX.25." % ctrl_type)

        return encoded_ctrl_field.to_bytes(1, byteorder='big')

    else:
        raise ValueError("Modulo 128 is not implemented")



def ax25_encode_address(callsign: str, ssid: int, is_last: bool, command_bit: bool = False) -> bytearray:
    """
    This function encodes the given info into an AX.25 compatible address field and returns the result as a bytearray.

    Parameters:
    callsign:    The callsign is made up of upper-case alpha and numeric ASCII characters only.
    ssid:        The SSID is a four-bit integer that uniquely identifies multiple stations using the
                 same amateur callsign.
    is_last:     The last byte of the address is set to “0” to indicate the address field contains more
                 information, or to “1”, to indicate that this is the last address in the HDLC address field.
    command_bit: Optional argument to specify wheter to set the command bit or not.
                 More info can be found from 6.1.2. Command/Response Procedure

    Returns:
    bytearray: Radio amateur callsign in bytes when everything went as expected, otherwise Exception is raised
    """
    # Initialize the callsign
    callsign_in_bytes = None

    # SSID is one byte
    if ssid < 0 or ssid > 15:
        raise ValueError("Valid SSID is from 0 to 15. Given SSID was %i." % (ssid))

    # Check if callsign is 6 characters or less
    callsign_length = len(callsign)
    if callsign_length < 1 or callsign_length > 6:
        raise ValueError("Valid callsign is from 1 to 6 characters in length. Given callsign was %i characters "\
            "long." % (len(callsign)))

    # Check if callsign only contains alpha numeric ASCII characters
    callsign_in_bytes = bytearray(callsign.upper(), "ascii")

    # If a callsign is less than 6 characters long, it must be padded with blanks.
    callsign_in_bytes.extend(bytearray(" " * (6-callsign_length), "ascii"))

    # Set the R bits to 1 in SSID byte as they are not implemented
    ssid |= 0x30

    # Check wheter to enable the command bit or not
    if command_bit:
        ssid |= 0x40

    # Append the SSID to the callsign byte
    callsign_in_bytes.append(ssid)

    # Shift every byte one bit to the left
    for i in range(7):
        callsign_in_bytes[i] = callsign_in_bytes[i] << 1

    if is_last:
        callsign_in_bytes[-1] |= 1

    return callsign_in_bytes


def ax25_decode_address(encoded_callsign: bytearray) -> (str, int, bool, bool):
    """
    This function decodes the given bytearray from an AX.25 compatible address field and returns the result as a
    tuple of arguments containing the decoded info.

    Parameters:
    encoded_callsign: Radio amateur callsign in bytes

    Returns:
    str: Radio amateur callsign str in ASCII when everything went as expected, otherwise Exception is raised
    int: four-bit SSID integer.
    bool: If this is true then the address was the last address in the HDLC address field.
    bool: If this is true then the command bit was set in the address field.
    """
    decoded_callsign = None
    decoded_ssid     = None
    is_last          = None
    command_bit_set  = None
    callsign_length  = len(encoded_callsign)

    if callsign_length != 7:
        raise ValueError("Invalid callsign length, expected 7 but got %i." % (callsign_length))

    # Check if it's the last address before shifting everything back
    is_last = bool(encoded_callsign[-1] & 0x01)

    # Shift every ASCII byte back to initial position
    # Also do a check if the lowest bit is zero as it should be
    # @NOTE: This doesn't catch all possible problems
    for i in range(6):
        if encoded_callsign[i] & 0x01:
            raise ValueError("Encoded callsign ASCII %i byte had LSB set to 1." % (i))
        encoded_callsign[i] = encoded_callsign[i] >> 1

    # Finally shift the last byte right as well
    encoded_callsign[6] = encoded_callsign[6] >> 1

    # Get the decoded callsign and check if it contains ascii characters
    decoded_callsign = encoded_callsign[:6].decode("ascii").strip()

    # Get the SSID
    decoded_ssid = int(encoded_callsign[-1] & 0xF)

    # Check if the command bit was set
    command_bit_set = bool(encoded_callsign[-1] & 0x40)

    return decoded_callsign, decoded_ssid, is_last, command_bit_set


def ax25_create_frame(dst: str, dst_ssid: int, src: str, src_ssid: int, ctrl_type: AX25_Ctrl_Fields, info: bytearray,
        **ax25_config) -> bytearray:
    """
    Given the configuration, the function returns a valid AX.25 as a bytearray.

    Parameters:
    dst/src:     The callsign is made up of upper-case alpha and numeric ASCII characters only.
    ssid:        The SSID is a four-bit integer that uniquely identifies multiple stations using
                 the same amateur callsign.
    ctrl_field:  The control field identifies the type of frame being sent. Has to be a value from the AX25_Ctrl_Fields
                 enum.
    info:        AX.25 frame payload as a bytearray.
    ax25_config: AX.25 frame configuration fields inside a dictionary. To see what fields are required for your specific
                 frame have a look at the specific encoding functions.

    Returns:
    bytearray that contains the encoded AX.25 frame.
    """
    ax25_frame = bytearray([0x7E])
    ax25_frame.extend( ax25_encode_address(dst, dst_ssid, False) )
    ax25_frame.extend( ax25_encode_address(src, src_ssid, True) )
    ax25_frame.extend( ax25_encode_control_field(ctrl_type, **ax25_config) )

    if ctrl_type in AX25_Ctrl_Groups.PID_FIELD and len(info):
        ax25_frame.extend( ax25_encode_pid_field(ctrl_type, ax25_config["pid_field"]) )
    else:
        raise ValueError("AX.25 doesn't support info field for %s ctrl type." % ctrl_type)

    if ctrl_type in AX25_Ctrl_Groups.INFO_FIELD and len(info):
        # The easiest way to create a bytearray info field is to use bytearray.fromhex("hex_string")
        ax25_frame.extend( info )
    else:
        raise ValueError("AX.25 doesn't support info field for %s ctrl field." % ctrl_type)

    ax25_frame.extend( ax25_crc_16_x25(ax25_frame[1:]) )

    # Add final AX.25 flag
    ax25_frame.extend(bytes([0x7E]))

    return ax25_frame

def internal_disassembly(ax25_frame: bytearray, current_frame_idx: int ) -> dict:
    """
    Meant for internal use by the ax.25 library only!
    """

    disassembled_frame = { }

    # The address field of all frames consists of a destination, source
    # and (optionally) two Layer 2 repeater subfields
    for i in range(4):
        callsign, _, is_last, _ = ax25_decode_address( ax25_frame[current_frame_idx: current_frame_idx + 7] )
        current_frame_idx += 7

        if i == 0:
            if is_last:
                raise ValueError("Last bit of dst SSID byte shouldn't be 1!")
            else:
                disassembled_frame["dst_callsign"] = callsign
                disassembled_frame["dst_ssid_byte"] = ax25_frame[current_frame_idx - 1]

        elif i == 1:
            if is_last:
                disassembled_frame["src_callsign"] = callsign
                disassembled_frame["src_ssid_byte"] = ax25_frame[current_frame_idx - 1]
                break
            else:
                disassembled_frame["repeater1_callsign"] = callsign
                disassembled_frame["repeater1_ssid_byte"] = ax25_frame[current_frame_idx - 1]

        elif i == 2:
            if is_last:
                disassembled_frame["src_callsign"] = callsign
                disassembled_frame["src_ssid_byte"] = ax25_frame[current_frame_idx - 1]
                break
            else:
                disassembled_frame["repeater2_callsign"] = callsign
                disassembled_frame["repeater2_ssid_byte"] = ax25_frame[current_frame_idx - 1]

        else:
            if is_last:
                disassembled_frame["src_callsign"] = callsign
                disassembled_frame["src_ssid_byte"] = ax25_frame[current_frame_idx - 1]
                break
            else:
                raise ValueError("Last bit wasn't set but %i is the 4th address field!" % ax25_frame[ (i + 1) * 6] )

    # Parse control field
    disassembled_frame["ctrl_field"] = ax25_frame[current_frame_idx]
    current_frame_idx += 1

    # Check the frame is a I or a U frame
    if not (disassembled_frame["ctrl_field"] << 6) or (disassembled_frame["ctrl_field"] & AX25_Ctrl_Fields.AX25_CTRL_UI.value):
        disassembled_frame["pid_field"] = ax25_frame[current_frame_idx]
        current_frame_idx += 1

    return disassembled_frame, current_frame_idx

def ax25_disassemble_raw_frame(ax25_frame: bytearray) -> dict:
    """
    The function expects an input in the form of a valid AX.25 bytearray i.e 0x7E, ctrl, (optional) PID, INFO, FCS, 0x7E
    It takes the AX.25 bytearray and disassembles it into individual pieces and converts the callsigns into human
    readable form.

    Parameters:
    ax25_frame: An AX.25 frame in the form of a bytearray

    Returns:
    dictionary that contains the disassembled AX.25 frame pieces
    """

    # A valid frame starts with a 0x7E
    if ax25_frame[0] != 0x7E or ax25_frame[-1] != 0x7E:
        raise ValueError("A valid AX.25 frame starts and ends with a 0x7E flag. Currently the first byte is %i and "
            "the last byte is %i." % ax25_frame[0], ax25_frame[-1])

    disassembled_frame, current_frame_idx = internal_disassembly(ax25_frame, 1)

    # Get the info field
    disassembled_frame["info"] = ax25_frame[current_frame_idx:-3]

    # Get the FCS
    disassembled_frame["fcs"] = ax25_frame[-3:-1]

    return disassembled_frame

def ax25_disassemble_kiss_frame(ax25_frame: bytearray) -> dict:
    """
    The function expects an input in the form of a TNC outputted AX.25 bytearray i.e 0x7E, ctrl, (optional) PID, INFO, 0x7E
    It takes the AX.25 bytearray and disassembles it into individual pieces and converts the callsigns into human
    readable form.

    Parameters:
    ax25_frame: An AX.25 frame in the form of a bytearray

    Returns:
    dictionary that contains the disassembled AX.25 frame pieces
    """

    disassembled_frame, current_frame_idx = internal_disassembly(ax25_frame, 1)

    # Get the info field
    disassembled_frame["info"] = ax25_frame[current_frame_idx:]

    # Get the FCS
    disassembled_frame["fcs"] = "N/A"

    return disassembled_frame