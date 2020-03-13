import yaml
import json

knot_module = "cznic-resolver-knot:"
root_node = "cznic-resolver-common:dns-resolver:\n"

conversion_list= [
    "kresd-instances",
    "auto-start",
    "auto-cache-gc",
    "kresd-names",
    "modules",
    "hosts-file",
    "hint",
    "kind",
    "sticket-secret",
    "http",
    "storage",
    "garbage-collector"
]


def import_file(file_path: str):

    file = open(file_path, 'r')
    yaml_str = file.read()
    file.close

    # add Tab/spaces on each line
    yaml_str = '    '.join(yaml_str.splitlines(True))
    # add 'cznic-resolver-common:dns-resolver:' root node
    yaml_str = root_node + yaml_str

    # add 'cznic-resolver-knot:' to each knot-resolver specific configuration
    for string in conversion_list:
        yaml_str = yaml_str.replace(string, knot_module+string)

    print(yaml_str)

    # return dictionary
    return yaml.load(yaml_str,Loader=yaml.Loader)

def export_file(file_path: str, data):

    yaml_str = yaml.dump(data, Dumper=yaml.Dumper, indent=4)

    yaml_str = yaml_str.replace(root_node, "")
    # remove 'cznic-resolver-knot:' to each knot-resolver specific configuration
    yaml_str = yaml_str.replace(knot_module, "")

    print(yaml_str)

    file = open(file_path, 'w')
    file.write(yaml_str)
    file.close