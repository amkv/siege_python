#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import os
import argparse
import requests
import datetime
import time
from termcolor import cprint, colored
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool

def argumentsParser():
    '''Parse arguments of command line'''
    parser = argparse.ArgumentParser(description = '''clone of siege utility''', \
    epilog = '''(c) April 2017. Artem Kalmykov, 42US''')
    # parser.add_argument('-b', '--nopause', action = 'store_true', default = False, help = 'No pauses')
    parser.add_argument('-c', '--concurent', nargs = '?', type = int, default = 1, help = 'parallel repeats')
    parser.add_argument('-r', '--repeat', nargs = '?', type = int, default = 1, help = 'how many repeats')
    parser.add_argument('-v', '--verbose', action = 'store_true', default = False, help = 'show more info while execution')
    # parser.add_argument('-t', '--time', nargs = '?') # h m s
    parser.add_argument('-f', '--file', nargs = '?', default = None, help = 'open URLs from the file')
    # parser.add_argument('-i', '--internet', nargs = '?')
    parser.add_argument('-V', '--version', action = 'version', help = 'show version', version='%(prog)s ' + '0.0.7')
    parser.add_argument('-C', '--config', action = 'store_true', default = False, help = 'show the config file')
    parser.add_argument('-d', '--delay', nargs = '?', default = 0, help = 'set delay in ms between requests')
    # parser.add_argument('-e', '--header', nargs = '?')
    # parser.add_argument('-A', '--agent', nargs = '?')
    # parser.add_argument('-g', '--url', nargs = '?')
    # parser.add_argument('-l', '--log', action = 'store_true', default = False)
    # parser.add_argument('-o', '--timeout', action = 'store_true', default = False)
    parser.add_argument('url', nargs = '*', default = 'None', help = 'check this URL(s), format http://url.com')
    return parser

def print_arguments(flags):
    '''Iterate throught all arguments passed to the program'''
    print 'Arguments:'
    for key in flags.items():
        print str(key[0]) + " = " + str(key[1])
    print("-----start-----")

def print_result(info):
    '''Print results on the end'''
    print '\n------------------------------------------------------'
    print 'Hits:' + ' ' + str(info['hits'])
    # print 'Availability: ' + str(None) + ' %'
    print 'Elapsed time: ' + str(info['total']) + 'ms'
    # print 'Data transfered: ' + str(None)
    print 'Response time: ' + str(int(info['total'] / info['hits'])) + 'ms'
    # print 'Transaction rate: ' + str(None)
    # print 'Throughput: ' + str(None)
    # print 'Concurrency: ' + str(None)
    print 'Successful transactions: ' + str(info['ok'])
    print 'Failed transactions: ' + str(info['ko'])
    try:
        print 'Longest transaction: ' + str(int(info['max_response'].total_seconds() * 1000)) + 'ms'
    except:
        print "Longest transaction: no info"
    try:
        print 'Shortest transaction:  ' + str(int(info['min_response'].total_seconds() * 1000)) + 'ms'
    except:
        print "Shortest transaction: no info"
    print '------------------------------------------------------\n'

def set_info_time(info):
    '''Set response, max and min time'''
    info['response'] = info['end_response'] - info['start_response']
    if not info['min_response']:
        info['min_response'] = info['response']
    elif info['response'] < info['min_response']:
        info['min_response'] = info['response']
    if not info['max_response']:
        info['max_response'] = info['response']
    elif info['response'] > info['max_response']:
        info['max_response'] = info['response']
    if info['total'] != 0:
        info['total'] += info['response']
    else:
        info['total'] = info['response']

def make_one_request(each, info, flags):
    '''Make one request and set min/max time, status code and response time'''
    bad = False
    try:
        info['start_response'] = datetime.datetime.utcnow()
        if flags['verbose']:
            print "[connecting] ... " + colored (each, 'cyan') + ' at ' + str(info['start_response'])
        res = requests.get(each)
        info['status_code'] = res.status_code
        info['end_response'] = datetime.datetime.utcnow()
        if flags['verbose']:
            print "[connected] ... " + colored (each, 'cyan') + ' at ' + str(info['end_response'])
    except:
        print colored("[error] ", 'red') + each
        info['ko'] += 1
        bad = True
    if not bad:
        set_info_time(info)
        if info['status_code'] >= 200 and info['status_code'] <= 299:
            cprint(str(info['status_code']), 'green', end=' ')
            info['ok'] += 1
        elif info['status_code'] >= 300 and info['status_code'] <= 599:
            cprint(str(info['status_code']), 'magenta', end=' ')
        print('%dms %s') % (info['response'].total_seconds() * 1000, each)
    info['hits'] += 1

def make_requests(info, flags, url):
    '''Iterate throught all urls given as parametr'''
    start_time = datetime.datetime.utcnow()
    for i in range(flags['repeat']):
        for each in url:
            make_one_request(each, info, flags)
            time.sleep(int(flags['delay']) / 1000)
    end_time = datetime.datetime.utcnow()
    info['total'] = int((end_time - start_time).total_seconds() * 1000)

def init_info():
    '''Initialising dictionary for various info'''
    info = { \
            'hits' : 0, \
            'start_response' : None, \
            'end_response' : None, \
            'response' : None, \
            'max_response': None, \
            'min_response': None, \
            'total' : 0, \
            'status_code' : None, \
            'ok' : 0, \
            'ko' : 0, \
            }
    return info

def read_urls_from_file(name):
    '''Reading URLs from file'''
    if not os.path.isfile(name):
        print 'file ' + name + ' not exist'
        sys.exit(0)
    url = []
    try:
        with open(name, 'r') as f:
            for line in f:
                url.append(line.replace('\n', ''))
    except:
        print "wrong with reading from file"
        sys.exit(0)
    return url

def flags_checker(flags):
    '''Check flags before starting'''
    if flags['repeat'] <= 0:
        print "Repeat parameter shoud be greater then 0"
        sys.exit(0)
    if flags['config']:
        print "No config in this version, see you in the future"
        sys.exit(0)
    if flags['concurent'] <= 0:
        print "Concurent parameter shoud be greater then 0"
        sys.exit(0)
    if flags['delay'] < 0:
        print "Delay parameter shoud be positive number"
        sys.exit(0)
    elif flags['concurent'] >= 1001:
        print "Concurent parameter too big"
        sys.exit(0)
    if flags['url'] == 'None' and flags['file'] == None:
        print "No url provided"
        sys.exit(0)
    elif flags['url'] != 'None' and flags['file'] == None:
        return flags['url']
    elif flags['url'] != 'None' and flags['file'] != None:
        print "Competing urls sources"
        sys.exit(0)
    elif flags['url'] == 'None' and flags['file'] != None:
        return read_urls_from_file(flags['file'])

def main(argv):
    '''main method'''
    arguments = argumentsParser().parse_args(argv[1:])
    flags = vars(arguments)
    url = flags_checker(flags)
    if flags['verbose']: print_arguments(flags)
    info = init_info()
    pool = ThreadPool(flags['concurent'])
    pool.map(make_requests(info, flags, url), info)
    pool.close()
    pool.join()
    print_result(info)
    if flags['verbose']: print("-----end-----")

if __name__ == "__main__":
    main(sys.argv)
