from __future__ import print_function, unicode_literals
import six
import subprocess


def proc_output(args):
    out = subprocess.check_output(args)
    if not isinstance(out, six.text_type):
        out = out.decode("utf8")
    return out


def output_one(cmd):
    print(".. _`{}`:".format(cmd))

    header("+", "{} subcommand".format(cmd))

    print("**{}**:".format(cmd))
    print("")

    out = proc_output(["autocrypt", cmd, "-h"])
    if cmd == "mod-identity":
        out = out.replace("[notset|yes|no]", " " * 15)
    for line in out.splitlines():
        print("  " + line)
    print ("")


def header(underchar, msg):
    print("")
    print(msg)
    print(underchar * len(msg))
    print("")


if __name__ == "__main__":
    header("-", "subcommand reference |version|")

    x = proc_output(["autocrypt"])
    lines = x.splitlines()
    for i, line in enumerate(lines):
        if "Commands:" in line:
            found = [l.split()[0].strip() for l in lines[i+1:]]

    for sub in found:
        output_one(sub)

