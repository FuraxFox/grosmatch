#!/usr/bin/env python3
# pip install rich
#
# usage:
# grosmatch patterns.csv logfile1.log logfile2.log logfile3.log logfile3.log
#
import datetime
import re
import csv
import json

from sys import argv
from rich.pretty import pprint
from rich import print
from rich import inspect
from rich.console import Console

#Init
EXTRACT_RE = re.compile(r'\S+ -( |\w+)- \[(.*)\] "')    
import logging
from rich.logging import RichHandler

FORMAT = "%(message)s"
logging.basicConfig(
    level="INFO", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)

LOGGER = logging.getLogger("rich")

# Funcs
def read_patterns(filename):
    """
    Read the matching dates and patterns from a CSV file
    """
    LOGGER.info("reading rules from "+filename)
    with open(filename) as csvfile:
        patterns_reader = csv.reader(csvfile, delimiter=',', quotechar='"')
        rules = []
        linenum = 0
        for row in patterns_reader:
            if linenum == 0:
                linenum = linenum + 1
                continue
            rule = {}
            rule['begin'] = row[0]
            rule['end'] = row[1]
            try:
                rule['re'] = re.compile(row[2])
            except:
                LOGGER.exception("line :"+str(linenum)+" failed to compile Regex: "+ row[2])
            rules.append(rule)
            linenum = linenum + 1
    LOGGER.info(str(len(rules)) + " rules read from " + filename )
    return rules

def stamp_to_epoch(stamp):
    """
    convert a timestamp to epoch
    """
    #    print("stamp:["+stamp+"]")
    try:
        dt =datetime.datetime.strptime(stamp,"%d/%b/%Y:%H:%M:%S %z")
        return dt.timestamp()
    except:
        return None


def logline_to_stamp(line):
    """
    Return the timestamp part of a logline
    """
    res = re.search(EXTRACT_RE,line)
    if res is None:
        return None
    stamp = res.group(2)
    return stamp

def rule_to_descr(r):
    """
    return a description of a rule
    """
    return '['+r['begin']+','+r['end']+'] =' + str(r['re'])

def rule_key(r):
    """
    return key for sorting by end date
    """
    return r['end_e']

def lookup_rules(rules,e):
    """
    lookup applicable rules for a given epoch
    """
    if rules is None:
        return None
    if len(rules) == 0:
        return None
    if e > rules[-1]['end_e']:
        return None
    if e < rules[0]['begin_e']:
        return None 

    results= []
    for r in rules:
        if e > r['begin_e'] and e < r['end_e']:
            results.append(r)
        if e > r['end_e']:
            break

    if len(results) == 0:
        return None

    return results

def match_logline(rules_lookup,line):
    """
    Try to match a logline and return the matching rules as an array if any or None 
    """
    line.rstrip()

    # extract current log line timestamp and convert it to epoch
    stamp = logline_to_stamp(line)
    if stamp is None:
        LOGGER.error('failed to parse: '+line + '  stamp:', stamp) 
        return None
    e = stamp_to_epoch(stamp)
    if e is None:
        LOGGER.error ("failed to convert stamp to epoch:"+stamp)
        return None
    #LOGGER.debug("stamp ["+stamp+"] epoch:" + str(e) )

    # search rules applicable for 
    i_rules = lookup_rules(rules_lookup,e)
    if i_rules is None:
        #LOGGER.debug("no rules for ", stamp)
        return None
    #LOGGER.debug("rules "+str(i_rules) + " matching " +stamp )

    # applies selected rules
    matches = []
    for rule in i_rules:
        #LOGGER.debug("matching "+str(rule))
        #inspect(rule['re'])
        if re.search(rule['re'], line):
            #LOGGER.debug("line: " + line + "matches:" + str(rule) )
            matches.append( rule_to_descr(rule) )
    
    if len(matches)> 0 :
        return matches

    return None
    
def prepare_rules(raw_rules):
    """
    Pre-process rules for fast matching
    """
    rules_lookup = []
    for rule in raw_rules:
       begin_e = stamp_to_epoch( rule['begin'] )
       end_e   = stamp_to_epoch( rule['end' ]  )
       rule['begin_e'] = begin_e
       rule['end_e']   = end_e
       rules_lookup.append( rule )        
    rules_lookup = sorted( rules_lookup, key=rule_key)
    #inspect(rules_lookup)
    return rules_lookup

# Main
def main():
    # parse files entries
    matches   = {}
    patterns  = argv[1]
    filenames = argv[2:] 

    # read match rules from CSV file
    rules = read_patterns(patterns)

    # create rules lookup
    rules_lookup = prepare_rules(rules)
    pprint(rules_lookup)
    
    # for each file
    global_file_matches=0
    for fname in filenames :
        LOGGER.info("parsing "+ fname)
        with open(fname) as f:
            file_matches = 0
            # check each line for matches
            for line in f:
                matching = match_logline(rules_lookup,line)
                if not matching is None:
                    matches[line] = matching
                    file_matches = file_matches + len(matching)
            
            global_file_matches = global_file_matches + file_matches
            LOGGER.debug("file counts: matches:"+str(file_matches) )
    LOGGER.info("end of analysis: nb matches "+str(global_file_matches))

    # save results
    with open("output.json","w") as output:
        json.dump(matches,output, indent=2)

################################" 
if __name__ == "__main__":
    console = Console()
    try:
        main()
    except Exception:
        console.print_exception(max_frames=20)

 
