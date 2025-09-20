from lxml import etree
from collections import defaultdict
import argparse
import os

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

        valuable = ["user","pass","login","comment","name"]
        if any(keyword in node.tag.lower() for keyword in valuable):
            value = extract_value(node)

            if value == "" and has_inherited_flag(node):
                value = get_inherited_value(node, node.tag)

            if value is not None and len(value) > 0:
                entry = ("/".join(path), value)
                if entry not in seen:
                    results.append(entry)
                    seen.add(entry)

        for child in node:
            recurse(child, path)

    recurse(root)
    return results

def group_credentials(creds):
    """
    Group credentials by the "parent node" before the last segment in the path.
    E.g., root/basenode/nodes/group/data/mqtt_user -> group/data
    """
    grouped = defaultdict(list)
    for path, value in creds:
        parts = path.split("/")
        # Take the last 2 segments as group (like "group/data" or "probenode/data")
        if len(parts) >= 2:
            group = "/".join(parts[-3:-1])  # adjust depth if needed
        else:
            group = "root"
        name = parts[-1]
        grouped[group].append((name, value))
    return grouped

def print_grouped_creds(grouped):
    for group, items in grouped.items():
        print(f"\n=== {group} ===")
        for name, value in items:
            print(f"{name:40} : {value}")


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
    grouped = group_credentials(creds)
    print_grouped_creds(grouped)

