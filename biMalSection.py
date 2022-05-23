

import pefile
import sys
import argparse
import os
import pprint
import networkx
import re
from networkx.drawing.nx_agraph import write_dot
import collections
from networkx.algorithms import bipartite

args = argparse.ArgumentParser("Visualize shared hostnames between a directory of malware samples")
args.add_argument("target_path",help="directory with malware samples")
args.add_argument("output_file",help="file to write DOT file to")
args.add_argument("malware_projection",help="file to write DOT file to")
args.add_argument("hostname_projection",help="file to write DOT file to")
args = args.parse_args()
network = networkx.Graph()


# search the target directory for valid Windows PE executable files


allSections = []
for root,dirs,files in os.walk(args.target_path):
    for path in files:
        # try opening the file with pefile to see if it's really a PE file
        try:
            pe = pefile.PE(os.path.join(root,path))
        except pefile.PEFormatError:
            continue

        network.add_node(path,label=path[:32],color='black',penwidth=5,bipartite=0)
        mySections = []

        for section in pe.sections:
            secName = section.Name.decode(encoding='UTF-8').strip(b'\x00'.decode())
            if secName not in allSections:
                allSections.append(secName)
                network.add_node(secName,label=secName,color='blue', penwidth=10,bipartite=1)
            if secName not in mySections:
                mySections.append(secName)
                network.add_edge(secName,path,penwidth=2)

        if mySections:
            print("Extracted sections from:",path)
            pprint.pprint(mySections)

# write the dot file to disk
write_dot(network, args.output_file)
malware = set(n for n,d in network.nodes(data=True) if d['bipartite']==0)
sectionName = set(network)-malware

# use NetworkX's bipartite network projection function to produce the malware
# and sectionName projections
malware_network = bipartite.projected_graph(network, malware)
sectionName_network = bipartite.projected_graph(network, sectionName)

# write the projected networks to disk as specified by the user
write_dot(malware_network,args.malware_projection)
write_dot(sectionName_network,args.sectionName_projection)
