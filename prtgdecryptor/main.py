from argparse import ArgumentParser, BooleanOptionalAction, FileType
from collections import defaultdict
from html import escape
from typing import TextIO
from xml.etree import ElementTree
import re

import lxml.etree as etree


def main() -> None:
    entrypoint = ArgumentParser()
    parsers = entrypoint.add_subparsers(dest='command', required=True)

    parser = parsers.add_parser('file')
    parser.add_argument('xml', type=FileType(mode='r'), default='-', help='Path to input file')
    parser.add_argument('-o', '--output', type=FileType(mode='w'), default='-', help='Path to output file')
    parser.add_argument('--raw', action=BooleanOptionalAction, help='Generate raw XML output, defaults to pretty HTML')

    parser = parsers.add_parser('blob')
    parser.add_argument('data')
    parser.add_argument('-g', '--guid', required=True)

    opts = entrypoint.parse_args()

    if opts.command == 'file' and not opts.raw:
        creds = extract_valuables(opts.xml)
        generate_html(creds, opts.output)
        return

    if opts.command == 'file':
        content = opts.xml.read()
        root = ElementTree.fromstring(content)
        guid = root.get('guid')
        assert guid
    elif opts.command == 'blob':
        content = opts.data
        guid = opts.guid
    else:
        raise RuntimeError('unreachable')
    cipher = PaeCipherAES256(guid=guid)
    print(re.sub(r'([A-Z0-9]+={1,10})', lambda m: replacer(cipher, m), content), end='')


def replacer(cipher: 'PaeCipherAES256', match: re.Match) -> str:
    ciphertext = match.group(1)
    try:
        plaintext = cipher.decrypt(ciphertext, decode=True)
        # dont know why this happens, but it does
        if plaintext == ciphertext:
            return f'ENCRYPTED:{ciphertext}'
        return f'DECRYPTED:{plaintext or ''}'
    except Exception as e:
        return f'FAILED:{e.__class__.__name__}'

# html output

def generate_html(results: list[tuple[str, dict[str, str]]], output_file: TextIO) -> None:
    # group by columns
    groups = defaultdict(list)
    for path, valuables in results:
        colset = frozenset(valuables.keys())
        groups[colset].append((path, valuables))

    html = [
        '<!DOCTYPE html>',
        '<html><head><meta charset="utf-8">',
        '<style>',
        'body { font-family: Arial, sans-serif; margin: 20px; }',
        'h2 { margin-top: 40px; }',
        'table { border-collapse: collapse; margin-bottom: 30px; table-layout: auto; }',
        'th, td { border: 1px solid #ccc; padding: 6px 12px; text-align: left; max-width: 600px; word-wrap: break-word; }',
        'th { background: #f2f2f2; }',
        'tr:nth-child(even) { background: #fafafa; }',
        '</style>',
        '</head><body>',
        '<h1>Extracted Credentials</h1>',
    ]

    for colset, entries in groups.items():
        colnames = list(colset)

        # ordering: user first, pass second, then rest
        user_cols = [c for c in colnames if 'user' in c.lower()]
        pass_cols = [c for c in colnames if 'pass' in c.lower()]
        other_cols = sorted(c for c in colnames if c not in user_cols + pass_cols)

        ordered_cols = user_cols + pass_cols + other_cols

        html.append('<table>')
        html.append('<tr>' + ''.join(f'<th>{escape(col)}</th>' for col in ordered_cols) + '</tr>')

        for path, valuables in entries:
            row = []
            for col in ordered_cols:
                val = valuables.get(col, '')
                val_html = escape(val).replace('\n', '<br>')
                if 'comment' in col.lower() and len(val) > 30:
                    display_val = escape(val[:30] + '...')
                    cell = f'<td title="{escape(val)}">{display_val}</td>'
                else:
                    cell = f'<td>{val_html}</td>'
                row.append(cell)
            html.append('<tr>' + ''.join(row) + '</tr>')

        html.append('</table>')

    html.append('</body></html>')

    output_file.write('\n'.join(html).encode('utf-8'))


def decrypt_xml_node(node: etree.Element, cipher: 'PaeCipher') -> None:
    """
    Recursively decrypt XML node text if a 'crypt' attribute is present.
    Handles <cell crypt="..."> and <item crypt="..."> structures.
    """
    # If this node itself has 'crypt', decrypt its text if it exists
    if node.get('crypt') and node.text and cipher:
        try:
            node.text = cipher.decrypt(node.text.strip(), decode=True)
        except Exception:
            pass

    # If <item crypt="...">, you might want to decrypt specific child nodes, e.g., <text>
    if node.tag.lower() == 'item' and node.get('crypt') and cipher:
        text_child = node.find('text')
        if text_child is not None and text_child.text:
            try:
                text_child.text = cipher.decrypt(text_child.text.strip(), decode=True)
            except Exception:
                pass

    # Recurse for children
    for child in node:
        decrypt_xml_node(child, cipher)


def extract_valuables(xml_file: TextIO) -> list[tuple[str, dict[str, str]]]:
    blacklist = ["cloudcredentials",
        "commentgroup",
        "dbcredentials",
        "lastlogin",
        "linuxloginmode",
        "mqttcredentials",
        "mqtt_user_credentials",
        "mqtt_use_user_credentials",
        "ms365credentialchanged",
        "ms365credentialsinherited",
        "ms365secretkeychanged",
        "opcua_use_user_credentials",
        "paessler-ciscomeraki-credentials_section",
        "paessler-ciscomeraki-credentials_section-credentials_group-api_endpoint",
        "paessler-dellemc-dellemc_credentials_section",
        "paessler-dellemc-dellemc_credentials_section-port_group-port",
        "paessler-fortigate-fortigate_credentials_section",
        "paessler-fortigate-fortigate_credentials_section-port_group-port",
        "paessler-hpe3par-hpe3par_credentials_section",
        "paessler-hpe3par-hpe3par_credentials_section-connection_group-port",
        "paessler-hpe3par-hpe3par_credentials_section-connection_group-protocol",
        "paessler-hpe3par-hpe3par_credentials_section-connection_group-ssh_port",
        "paessler-http-credentials_section",
        "paessler-http-credentials_section-credentials_group-authentication_method",
        "paessler-microsoftazure-azure_credentials_section",
        "paessler-microsoftazure-azure_credentials_section-credentials_group-management_endpoint",
        "paessler-mqtt-credentials",
        "paessler-mqtt-credentials-connection_mqtt-port",
        "paessler-mqtt-credentials-tls-active",
        "paessler-mqtt-credentials-tls-client_auth_active",
        "paessler-mqtt-credentials-tls-server_auth_active",
        "paessler-mqtt-credentials-user_credentials-active",
        "paessler-nats-credentials_section",
        "paessler-nats-credentials_section-credentials_group-authentication_method",
        "paessler-nats-credentials_section-credentials_group-tls_handshake_first",
        "paessler-nats-credentials_section-credentials_group-use_tls",
        "paessler-nats-credentials_section-port_group-port",
        "paessler-netapp-credentials_section",
        "paessler-netapp-credentials_section-connection_group-connection_security",
        "paessler-netapp-credentials_section-connection_group-port",
        "paessler-opcua-credentials",
        "paessler-opcua-credentials-connection_opcua-port",
        "paessler-opcua-credentials-connection_security-security_mode",
        "paessler-opcua-credentials-connection_security-security_policy",
        "paessler-opcua-credentials-user_authentication-user_auth_mode",
        "paessler-orchestra-credentials_orchestra_section",
        "paessler-orchestra-credentials_orchestra_section-credentials_orchestra_group-authentication",
        "paessler-orchestra-credentials_orchestra_section-port_orchestra_group-port",
        "paessler-orchestra-credentials_orchestra_section-protocol_orchestra_group-protocol",
        "paessler-orchestra-credentials_orchestra_section-timeout_orchestra_group-timeout",
        "paessler-prtgdatahub-credentials_section",
        "paessler-prtgdatahub-credentials_section-credentials_group-metrics_port",
        "paessler-redfish-redfish_credentials_section",
        "paessler-redfish-redfish_credentials_section-connection_group-port",
        "paessler-redfish-redfish_credentials_section-connection_group-protocol",
        "paessler-rest-authentication_section-authentication_group-login_auth_method",
        "paessler-rest-authentication_section-authentication_group-login_request_method",
        "paessler-rest-authentication_section-authentication_group-login_result_type",
        "podlogintype",
        "ssoenablelogin",
        "ssoprovidername",
        "trafficportname",
        "updateportname",
        "useproxycredentials",
        "usersettings",
        "usertype",
        "paessler-rest-authentication_section-authentication_group-auth_cookie_name",
        "paessler-rest-authentication_section-authentication_group-auth_header_name",
        "paessler-rest-authentication_section-authentication_group-login_cookie_name",
        "paessler-rest-authentication_section-authentication_group-login_header_name",
        "paessler-rest-authentication_section-authentication_group-login_json_path"
    ]

    tree = etree.parse(xml_file)
    root = tree.getroot()
    guid = root.get('guid')
    cipher = PaeCipherAES256(guid=guid)

    seen = set()
    results = []

    def get_inherited_value(node: etree.Element, tagname: str) -> str|None:
        """Walk up parents until a value for tagname is found inside their <data> section, with debug output."""
        parent = node.getparent()
        # if node is inside a <data> element, jump to its parent container
        if parent is not None and parent.tag.lower() == 'data':
            parent = parent.getparent()

        while parent is not None:
            # build a readable path for debug
            path = []
            temp = parent
            while temp is not None:
                path.insert(0, temp.tag)
                temp = temp.getparent()

            data_section = parent.find('data')
            if data_section is not None:
                match = data_section.find(tagname)
                if match is not None:
                    val = extract_value(match)
                    if val is not None:
                        return val
            parent = parent.getparent()

        return None

    def extract_value(node: etree.Element) -> str:
        '''Extract value from node or its <cell> children, decrypting if needed.'''
        values = []

        # handle multiple <cell> children
        for cell in node.findall('cell'):
            text = cell.text.strip() if cell.text else ''
            if text and cell.get('crypt') and cipher:
                # decrypt if 'crypt' attribute exists
                text = cipher.decrypt(text, decode=True)
            if text:
                values.append(text)

        # fallback to node text if no cells or no text extracted
        if not values and node.text and node.text.strip():
            values.append(node.text.strip())

        # join multiple cells with a space (or any separator you prefer)
        return '\n'.join(values)

    def has_inherited_flag(node) -> bool:
        '''Check if node has <flags><inherited/>.'''
        flags = node.find('flags')
        if flags is not None and flags.find('inherited') is not None:
            return True
        return False

    def recurse(node: etree.Element, path: list = []) -> list[tuple[str, dict[str, str]]]|None:
        if node.tag.lower() == 'history':
            return

        path = path + [node.tag]

        # collect valuables from this node's children
        valuables: dict[str, str] = {}
        valuables_list = ['user', 'pass', 'login', 'comment', 'name']

        for child in node:
            tag = child.tag.lower()
            if tag in blacklist:
                continue
            if any(keyword in tag for keyword in valuables_list):
                value = extract_value(child)

                if value == '' and has_inherited_flag(child):
                    value = get_inherited_value(child, child.tag)

                if value is not None and len(value) > 0:
                    valuables[tag] = value

        # if we found multiple valuables under the same parent: they belong together
        must_contain = ['pass','key','secret','cred']
        found = 0
        for key in valuables:
            lower_key = key.lower()
            for keyword in must_contain:
                if keyword in lower_key:
                    found = 1
        if found:
            entry = ('/'.join(path), valuables)
            hashable_entry = ('/'.join(path), frozenset(valuables.items()))
            if hashable_entry not in seen:
                results.append(entry)     # keep the nice dict in results
                seen.add(hashable_entry)  # store a hashable version in seen

        # keep recursing down
        for child in node:
            recurse(child, path)

    recurse(root)
    return results

# code below copied from https://github.com/yobabyte/decryptocollection/blob/9eb8188a869745931c164d297b1fbfaf17cbd9db/prtg/prtg_string_decryptor.py

from Crypto.Cipher import AES

from base64 import b32decode
from hashlib import sha256


class PaeCipher:
    _TEXT_ENCODINGS = ('ascii', )

    @property
    def key(self) -> bytes:
        return self._derive_key()

    def decrypt(self, data: bytes, decode: bool = True):
        decrypted = self._decrypt_impl(data)
        if decode:
            for encoding in self._TEXT_ENCODINGS:
                try:
                    return decrypted.decode(encoding)
                except:
                    pass
        else:
            return decrypted

    def _derive_key(self) -> bytes:
        raise NotImplementedError()

    def _decrypt_impl(self, data: bytes) -> bytes:
        raise NotImplementedError()


class PaeCipherAES256(PaeCipher):
    _KEY_PREFIX = '{FAE6C904-D2CC-453E-81E2-B6D3CFD69B92}'
    _TEXT_ENCODINGS = ('UTF-8', 'UTF-16LE')

    def __init__(self, guid: str, salt: str = '') -> None:
        self.guid = guid
        self.salt = salt or ''

    def _derive_key(self) -> bytes:
        return sha256((self._KEY_PREFIX + self.guid + self.salt).encode()).digest()

    def _decrypt_impl(self, data: bytes) -> bytes:
        data = b32decode(data)
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(self.key, AES.MODE_OFB, iv=iv)
        return cipher.decrypt(ct)


if __name__ == '__main__':
    main()
