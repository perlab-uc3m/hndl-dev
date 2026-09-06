#!/usr/bin/env python3
"""TLS handshake extraction from PCAPs via tshark."""

import binascii
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


RECORD_HANDSHAKE = 0x16


def run_tshark(
    command: list[str],
    pcap_file: Path,
    auxiliary_files: tuple[Path, ...] = (),
) -> subprocess.CompletedProcess:
    """Run tshark, staging inputs only when its AppArmor profile blocks them.

    Ubuntu's tshark AppArmor profile can permit dumpcap to create a PCAP under
    a home directory while denying tshark permission to reopen that same file.
    A retry from a private temporary directory preserves the original evidence
    and avoids weakening the host policy.  The fallback is intentionally used
    only for an explicit permission error.
    """
    result = subprocess.run(command, capture_output=True, text=True)
    permission_error = result.returncode != 0 and any(
        marker in result.stderr.lower()
        for marker in ("permission to read", "permission denied")
    )
    if not permission_error:
        return result

    sources = (Path(pcap_file), *(Path(path) for path in auxiliary_files))
    with tempfile.TemporaryDirectory(prefix="hndl-tshark-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        replacements = {}
        for index, source in enumerate(sources):
            staged = temp_dir / f"{index}-{source.name}"
            shutil.copyfile(source, staged)
            staged.chmod(0o600)
            replacements[str(source)] = str(staged)
        retry_command = [_replace_paths(argument, replacements) for argument in command]
        return subprocess.run(retry_command, capture_output=True, text=True)


def _replace_paths(argument: str, replacements: dict[str, str]) -> str:
    for original, staged in replacements.items():
        argument = argument.replace(original, staged)
    return argument


def hexdump_frame(pcap: Path, frame_no: int, port: int) -> bytes:
    """Extract raw frame bytes from PCAP using tshark -x."""
    cmd = [
        "tshark",
        "-o",
        "tcp.desegment_tcp_streams:true",
        "-o",
        "tls.desegment_ssl_records:true",
        "-d",
        f"tcp.port=={port},tls",
        "-r",
        str(pcap),
        "-Y",
        f"frame.number=={frame_no}",
        "-x",
    ]
    p = run_tshark(cmd, pcap)
    if p.returncode != 0:
        raise RuntimeError(p.stderr or "tshark -x failed")
    hex_bytes = []
    for line in p.stdout.splitlines():
        line = line.strip()
        if len(line) < 5:
            continue
        parts = line.split()
        if parts[0].endswith(":") or all(
            c in "0123456789abcdef" for c in parts[0].lower()
        ):
            for tok in parts[1:]:
                if len(tok) != 2:
                    break
                try:
                    int(tok, 16)
                    hex_bytes.append(tok)
                except ValueError:
                    break
    return binascii.unhexlify("".join(hex_bytes))


def find_first_frame(pcap: Path, display_filter: str, port: int) -> int:
    """Find first frame matching display filter."""
    cmd = [
        "tshark",
        "-o",
        "tcp.desegment_tcp_streams:true",
        "-o",
        "tls.desegment_ssl_records:true",
        "-d",
        f"tcp.port=={port},tls",
        "-r",
        str(pcap),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-e",
        "frame.number",
    ]
    p = run_tshark(cmd, pcap)
    if p.returncode != 0:
        return 0
    for line in p.stdout.splitlines():
        line = line.strip()
        if line.isdigit():
            return int(line)
    return 0


def iter_tcp_payloads(pcap: Path, port: int):
    """Yield (frame_no, payload) for TCP frames on port."""
    cmd = [
        "tshark",
        "-o",
        "tcp.desegment_tcp_streams:true",
        "-o",
        "tls.desegment_ssl_records:true",
        "-r",
        str(pcap),
        "-Y",
        f"tcp.port=={port} && tcp.len > 0",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "tcp.payload",
    ]
    p = run_tshark(cmd, pcap)
    if p.returncode != 0:
        return
    for line in p.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 2:
            continue
        fno, payload_hex = parts[0], parts[1]
        if not fno.isdigit() or not payload_hex:
            continue
        payload_hex = payload_hex.replace(":", "")
        try:
            payload = binascii.unhexlify(payload_hex)
        except Exception:
            continue
        yield int(fno), payload


def parse_first_handshake_from_payload(
    payload: bytes, expected_type: int
) -> bytes | None:
    """Scan TCP payload for TLS handshake record with expected type."""
    b = payload
    i = 0
    while i + 5 <= len(b):
        if b[i] == RECORD_HANDSHAKE and i + 5 <= len(b):
            rec_len = (b[i + 3] << 8) | b[i + 4]
            rec_start = i + 5
            rec_end = rec_start + rec_len
            if rec_end > len(b):
                i += 1
                continue
            if rec_start + 4 <= rec_end:
                hs_type = b[rec_start]
                hs_len = (
                    (b[rec_start + 1] << 16)
                    | (b[rec_start + 2] << 8)
                    | b[rec_start + 3]
                )
                total = 4 + hs_len
                if hs_type == expected_type and rec_start + total <= rec_end:
                    return b[rec_start : rec_start + total]
        i += 1
    return None


def get_first_tcp_stream_index(pcap: Path, port: int) -> int:
    """Find first tcp.stream index for traffic on port."""
    cmd = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        f"tcp.port=={port}",
        "-T",
        "fields",
        "-e",
        "tcp.stream",
    ]
    p = run_tshark(cmd, pcap)
    if p.returncode != 0:
        return -1
    for line in p.stdout.splitlines():
        s = line.strip()
        if s.isdigit():
            return int(s)
    return -1


def list_tcp_stream_indices(pcap: Path, port: int | None = None) -> list[int]:
    """Return unique TCP stream indices, optionally restricted to a port."""
    display_filter = "tcp" if port is None else f"tcp.port=={port}"
    cmd = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-e",
        "tcp.stream",
    ]
    p = run_tshark(cmd, pcap)
    if p.returncode != 0:
        return []
    seen = set()
    out = []
    for line in p.stdout.splitlines():
        s = line.strip()
        if s.isdigit():
            idx = int(s)
            if idx not in seen:
                seen.add(idx)
                out.append(idx)
    return out


def parse_follow_tcp_raw_output(raw_text: str) -> tuple[bytes, bytes]:
    """Parse tshark ``follow,tcp,raw`` output into its two endpoint streams."""
    node0 = bytearray()
    node1 = bytearray()
    saw_nodes = False
    for line in raw_text.splitlines():
        if line.startswith("Node 0:"):
            saw_nodes = True
            continue
        if line.startswith("Node 1:"):
            saw_nodes = True
            continue
        if not saw_nodes:
            continue
        encoded = line.strip()
        if not encoded or not re.fullmatch(r"[0-9a-fA-F]+", encoded):
            continue
        if len(encoded) % 2:
            raise ValueError("Odd-length hex data in tshark follow output")
        target = node1 if line.startswith("\t") else node0
        target.extend(binascii.unhexlify(encoded))
    return bytes(node0), bytes(node1)


def get_tcp_stream_bytes(pcap: Path, stream_index: int) -> tuple[bytes, bytes]:
    """Get reassembled TCP stream bytes using tshark follow,tcp,raw."""
    cmd = [
        "tshark",
        "-o",
        "tcp.desegment_tcp_streams:true",
        "-o",
        "tls.desegment_ssl_records:true",
        "-r",
        str(pcap),
        "-q",
        "-z",
        f"follow,tcp,raw,{stream_index}",
        "-P",
    ]
    p = run_tshark(cmd, pcap)
    if p.returncode != 0 or not p.stdout:
        raise RuntimeError(p.stderr or "follow,tcp,raw failed")
    return parse_follow_tcp_raw_output(p.stdout)


def extract_first_handshake_message(frame_bytes: bytes, expected_type: int) -> bytes:
    """Extract first handshake message from TLS record in frame."""
    b = frame_bytes
    i = 0
    while i + 5 <= len(b):
        if (
            b[i] == RECORD_HANDSHAKE
            and b[i + 1] == 0x03
            and b[i + 2] in (0x01, 0x02, 0x03, 0x04)
        ):
            rec_len = (b[i + 3] << 8) | b[i + 4]
            rec_start = i + 5
            rec_end = rec_start + rec_len
            if rec_end > len(b):
                break
            if rec_start + 4 <= rec_end:
                hs_type = b[rec_start]
                hs_len = (
                    (b[rec_start + 1] << 16)
                    | (b[rec_start + 2] << 8)
                    | b[rec_start + 3]
                )
                if hs_type != expected_type:
                    i = rec_end
                    continue
                total = 4 + hs_len
                if rec_start + total <= rec_end:
                    return b[rec_start : rec_start + total]
        i += 1
    raise ValueError("Failed to extract handshake message (likely fragmented)")


def parse_client_random_from_ch(client_hello_hs: bytes) -> bytes:
    """Extract 32-byte ClientHello.random."""
    if len(client_hello_hs) < 4 + 2 + 32:
        raise ValueError("ClientHello too short")
    start = 4 + 2
    end = start + 32
    return client_hello_hs[start:end]


def parse_cipher_from_server_hello(server_hello_hs: bytes) -> int:
    """Extract cipher suite from ServerHello."""
    if len(server_hello_hs) < 4 + 2 + 32 + 1 + 2 + 1:
        raise ValueError("ServerHello too short")
    i = 4 + 2 + 32
    sid_len = server_hello_hs[i]
    i += 1 + sid_len
    if i + 2 > len(server_hello_hs):
        raise ValueError("ServerHello truncated before cipher suite")
    cs = (server_hello_hs[i] << 8) | server_hello_hs[i + 1]
    return cs


def parse_client_keyshare_pub_from_ch(client_hello_hs: bytes) -> bytes | None:
    """Extract X25519 key_share from ClientHello extensions."""
    b = client_hello_hs
    if len(b) < 4 + 2 + 32 + 1:
        return None
    i = 4 + 2 + 32
    if i >= len(b):
        return None
    sid_len = b[i]
    i += 1 + sid_len
    if i + 2 > len(b):
        return None
    cs_len = (b[i] << 8) | b[i + 1]
    i += 2 + cs_len
    if i >= len(b):
        return None
    comp_len = b[i]
    i += 1 + comp_len
    if i + 2 > len(b):
        return None
    ext_total_len = (b[i] << 8) | b[i + 1]
    i += 2
    end = i + ext_total_len
    while i + 4 <= end and end <= len(b):
        etype = (b[i] << 8) | b[i + 1]
        elen = (b[i + 2] << 8) | b[i + 3]
        i += 4
        if i + elen > end:
            break
        if etype == 0x0033:
            j = i
            if j + 2 > i + elen:
                break
            list_len = (b[j] << 8) | b[j + 1]
            j += 2
            k = j
            list_end = j + list_len
            while k + 4 <= list_end and list_end <= i + elen:
                group = (b[k] << 8) | b[k + 1]
                k += 2
                kx_len = (b[k] << 8) | b[k + 1]
                k += 2
                if k + kx_len > list_end:
                    break
                if group == 0x001D:
                    return b[k : k + kx_len]
                k += kx_len
        i += elen
    return None


def parse_server_keyshare_pub_from_sh(server_hello_hs: bytes) -> bytes | None:
    """Extract X25519 key_share from ServerHello extensions."""
    b = server_hello_hs
    if len(b) < 4 + 2 + 32 + 1 + 2 + 1 + 2:
        return None
    i = 4 + 2 + 32
    sid_len = b[i]
    i += 1 + sid_len + 2 + 1
    ext_total_len = (b[i] << 8) | b[i + 1]
    i += 2
    end = i + ext_total_len
    while i + 4 <= end and end <= len(b):
        etype = (b[i] << 8) | b[i + 1]
        elen = (b[i + 2] << 8) | b[i + 3]
        i += 4
        if i + elen > end:
            break
        if etype == 0x0033:
            j = i
            if j + 4 > i + elen:
                break
            group = (b[j] << 8) | b[j + 1]
            j += 2
            kx_len = (b[j] << 8) | b[j + 1]
            j += 2
            if j + kx_len > i + elen:
                break
            if group == 0x001D:
                return b[j : j + kx_len]
        i += elen
    return None


def parse_new_session_ticket(nst_msg: bytes) -> dict:
    """Parse NewSessionTicket handshake message (type 4) to extract ticket_nonce.

    Format: type(1) | length(3) | lifetime(4) | age_add(4) | nonce_len(1) | nonce | ticket_len(2) | ticket | exts
    """
    if len(nst_msg) < 13 or nst_msg[0] != 4:
        raise ValueError("Invalid NewSessionTicket message")

    offset = 4  # Skip type + length
    offset += 8  # Skip lifetime + age_add

    nonce_len = nst_msg[offset]
    offset += 1

    if offset + nonce_len > len(nst_msg):
        raise ValueError("Truncated nonce field")

    ticket_nonce = nst_msg[offset : offset + nonce_len]
    offset += nonce_len

    if offset + 2 > len(nst_msg):
        raise ValueError("Truncated ticket_len field")

    ticket_len = (nst_msg[offset] << 8) | nst_msg[offset + 1]
    offset += 2

    if offset + ticket_len > len(nst_msg):
        raise ValueError("Truncated ticket field")

    ticket = nst_msg[offset : offset + ticket_len]

    return {
        "ticket_nonce": ticket_nonce,
        "ticket": ticket,
    }


def parse_client_hello_without_binders(ch_msg: bytes) -> bytes:
    """Remove PSK binders from ClientHello for transcript hash computation.

    Returns partial ClientHello ending right before binders (for transcript_hash).
    """
    if len(ch_msg) < 38 or ch_msg[0] != 1:
        return ch_msg

    # Navigate to extensions
    offset = 4  # type + length
    offset += 2  # legacy_version
    offset += 32  # random

    if offset >= len(ch_msg):
        return ch_msg

    session_id_len = ch_msg[offset]
    offset += 1 + session_id_len

    if offset + 2 > len(ch_msg):
        return ch_msg

    cipher_suites_len = (ch_msg[offset] << 8) | ch_msg[offset + 1]
    offset += 2 + cipher_suites_len

    if offset >= len(ch_msg):
        return ch_msg

    compression_len = ch_msg[offset]
    offset += 1 + compression_len

    if offset + 2 > len(ch_msg):
        return ch_msg

    exts_len = (ch_msg[offset] << 8) | ch_msg[offset + 1]
    exts_start = offset + 2
    exts_end = exts_start + exts_len
    offset = exts_start

    # Scan for PSK extension (type 41)
    while offset + 4 <= exts_end:
        ext_type = (ch_msg[offset] << 8) | ch_msg[offset + 1]
        ext_len = (ch_msg[offset + 2] << 8) | ch_msg[offset + 3]

        if ext_type == 41:  # pre_shared_key
            # PSK must be last, truncate before binders
            if offset + 4 + ext_len > len(ch_msg):
                break

            psk_data_offset = offset + 4
            # identities_len(2) + identities + binders_len(2) + binders
            if psk_data_offset + 2 > len(ch_msg):
                break

            identities_len = (ch_msg[psk_data_offset] << 8) | ch_msg[
                psk_data_offset + 1
            ]
            binders_offset = psk_data_offset + 2 + identities_len

            if binders_offset > len(ch_msg):
                break

            # Truncate at binders_len field
            # Adjust extension length to exclude binders
            truncate_point = binders_offset

            # Recompute lengths
            new_exts_len = truncate_point - exts_start
            new_ch_len = truncate_point - 4

            result = bytearray(ch_msg[:truncate_point])
            # Update handshake length
            result[1] = (new_ch_len >> 16) & 0xFF
            result[2] = (new_ch_len >> 8) & 0xFF
            result[3] = new_ch_len & 0xFF
            # Update extensions length
            result[exts_start - 2] = (new_exts_len >> 8) & 0xFF
            result[exts_start - 1] = new_exts_len & 0xFF

            return bytes(result)

        offset += 4 + ext_len

    return ch_msg


def extract_decrypted_handshake_from_tshark(
    pcap_file: Path, keylog_file: Path, frame_number: int = None, debug: bool = False
):
    """Decrypt TLS handshake messages from PCAP using tshark and a keylog file."""
    cmd = [
        "tshark",
        "-r",
        str(pcap_file),
        "-o",
        f"tls.keylog_file:{keylog_file}",
    ]

    if frame_number is not None:
        cmd.extend(["-Y", f"frame.number == {frame_number}"])

    cmd.append("-x")

    if debug:
        print(f"[dbg] Running: {' '.join(cmd)}")

    result = run_tshark(cmd, pcap_file, (keylog_file,))

    if result.returncode != 0:
        if debug:
            print(f"[dbg] tshark error: {result.stderr}")
        return []

    decrypted_messages = []
    in_decrypted = False
    hex_lines = []

    for line in result.stdout.split("\n"):
        if "Decrypted TLS" in line:
            if hex_lines:
                hex_data = "".join(hex_lines)
                try:
                    decrypted_messages.append(bytes.fromhex(hex_data))
                except ValueError:
                    pass
                hex_lines = []
            in_decrypted = True
        elif in_decrypted:
            if re.match(r"^[0-9a-f]{4}\s", line):
                hex_part = line[6:54]
                hex_bytes = hex_part.replace(" ", "")
                hex_lines.append(hex_bytes)
            elif line.strip() == "":
                if hex_lines:
                    hex_data = "".join(hex_lines)
                    try:
                        decrypted_messages.append(bytes.fromhex(hex_data))
                    except ValueError:
                        pass
                    hex_lines = []
                in_decrypted = False

    if hex_lines:
        hex_data = "".join(hex_lines)
        try:
            decrypted_messages.append(bytes.fromhex(hex_data))
        except ValueError:
            pass

    # A decrypted TLS record may contain several handshake messages followed
    # by the TLSInnerPlaintext content-type byte.  Return protocol messages,
    # rather than treating the entire record as one message.
    parsed_messages = []
    for plaintext in decrypted_messages:
        offset = 0
        while offset + 4 <= len(plaintext):
            msg_len = int.from_bytes(plaintext[offset + 1 : offset + 4], "big")
            total = 4 + msg_len
            if total < 4 or offset + total > len(plaintext):
                break
            parsed_messages.append(plaintext[offset : offset + total])
            offset += total

    if debug and parsed_messages:
        print(f"[dbg] Extracted {len(parsed_messages)} decrypted handshake messages")
        for msg in parsed_messages:
            if len(msg) >= 4:
                msg_type = msg[0]
                type_names = {
                    4: "NewSessionTicket",
                    8: "EncryptedExtensions",
                    11: "Certificate",
                    15: "CertificateVerify",
                    20: "Finished",
                }
                type_name = type_names.get(msg_type, f"Type{msg_type}")
                print(f"[dbg]   {type_name} ({msg_type}): {len(msg)} bytes")

    return parsed_messages


def verify_tls_http_request(
    pcap_file: Path, keylog_file: Path, port: int, debug: bool = False
) -> bool:
    """Prove that derived TLS secrets expose the captured HTTP request."""
    cmd = [
        "tshark",
        "-r",
        str(pcap_file),
        "-o",
        f"tls.keylog_file:{keylog_file}",
        "-d",
        f"tcp.port=={port},tls",
        "-T",
        "fields",
        "-e",
        "http.request.method",
        "-e",
        "http.request.uri",
        "-e",
        "tls.segment.data",
    ]
    result = run_tshark(cmd, pcap_file, (keylog_file,))
    if debug and result.returncode != 0:
        print(f"[dbg] tshark application-data validation failed: {result.stderr}")
    if result.returncode != 0:
        return False
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if fields and fields[0].strip() == "GET":
            return True
        for value in fields[2:]:
            try:
                plaintext = bytes.fromhex(value.replace(":", "").replace(",", ""))
            except ValueError:
                continue
            if b"GET / HTTP/1.0" in plaintext:
                return True
    return False


def verify_quic_stream_data(
    pcap_file: Path, keylog_file: Path, port: int, debug: bool = False
) -> bool:
    """Prove that derived QUIC secrets expose known application stream data."""
    cmd = [
        "tshark",
        "-r",
        str(pcap_file),
        "-o",
        f"tls.keylog_file:{keylog_file}",
        "-d",
        f"udp.port=={port},quic",
        "-Y",
        "quic.stream_data",
        "-T",
        "fields",
        "-e",
        "quic.stream_data",
    ]
    result = run_tshark(cmd, pcap_file, (keylog_file,))
    if debug and result.returncode != 0:
        print(f"[dbg] tshark QUIC application-data validation failed: {result.stderr}")
    if result.returncode != 0:
        return False
    decoded = bytearray()
    for line in result.stdout.splitlines():
        for value in line.split(","):
            try:
                decoded.extend(bytes.fromhex(value.replace(":", "").strip()))
            except ValueError:
                continue
    return b"GET / HTTP/1.0" in decoded or b"A" * 32 in decoded
