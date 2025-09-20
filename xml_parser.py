from lxml import etree
from collections import defaultdict
import argparse
import os
from html import escape

def generate_html(results, output_file="output.html"):
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
        "table { border-collapse: collapse; margin-bottom: 30px; width: 100%; }",
        "th, td { border: 1px solid #ccc; padding: 6px 12px; text-align: left; }",
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
                if "comment" in col.lower() and len(val) > 30:
                    display_val = escape(val[:30] + "…")
                    cell = f"<td title='{escape(val)}'>{display_val}</td>"
                else:
                    cell = f"<td>{escape(val)}</td>"
                row.append(cell)
            html.append("<tr>" + "".join(row) + "</tr>")



        html.append("</table>")

    html.append("</body></html>")

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(html))

    print(f"[+] HTML report written to {os.path.abspath(output_file)}")

def parse_xml(xml_file):
    tree = etree.parse(xml_file)
    root = tree.getroot()

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
        """Extract value from node or its <cell>."""
        cell = node.find("cell")
        if cell is not None and cell.text and cell.text.strip():
            return cell.text.strip()

        if node.text and node.text.strip():
            return node.text.strip()

        return ""

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



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract user/password/name/comment values from PRTG XML"
    )
    parser.add_argument("-i", "--input", required=True, help="Path to XML input file")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: File '{args.input}' does not exist.")
        exit(1)

    creds = parse_xml(args.input)
    generate_html(creds)

