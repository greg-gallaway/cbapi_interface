import cbapi
import sys, time
import optparse
from cbapi.util.live_response_helpers import LiveResponseHelper

'''
This script allows the user to interact with a carbon black server from command
line. You are able to display server info, perform a process search either with
one argument or from a file containing many args.

example usage:

#Displaying Server Info
#
gregory@Gregorys-MBP:~/Documents/slaitcode/webapp$ python cbapi_interface.py
--cburl=https://cbserver.example.com --apitoken=73acn5d8dk5mcjvjdjxxxxx4xxxxxx5aaabaaaxx
--no-ssl-verify --server-info


Server: https://cbserver.example.com
--------------------------------------------------------------------------------
binaryPageSize                 : 10
linuxInstallerExists           : True
binaryOrder                    :
banningEnabled                 : True
timestampDeltaThreshold        : 5
maxRowsSolrReportQuery         : 10000
osxInstallerExists             : True
version_release                : 5.1.0-3
liveResponseAutoAttach         : True
version                        : 5.1.0.150914.1400
cblrEnabled                    : True
processOrder                   :
processPageSize                : 10
vdiGloballyEnabled             : False
searchExportCount              : 1000
maxSearchResultRows            : 1000

#Perfroming Binary search from single argument
#
gregory@Gregorys-MBP:~/Documents/app$ python cbapi_interface.py -
-cburl=https://cbserver.example.com
--apitoken=73acn5d8dk5mcjvjdjxxxxx4xxxxxx5aaabaaaxx --no-ssl-verify --binary-search='calc'

Displayed Results    : 1
Total Results        : 1
QTime                : 14ms


#Conducting process search from a file of queries
#the file test-file.txt contains 3 lines with the strings "calc.exe", "GRR",
#and "lsass.exe"
#
gregory@Gregorys-MBP:~/Documents/app/cbapi_interface$ python cbapi_interface.py
--cburl=https://cbserver.example.com --apitoken=73acn5d8dk5mcjvjdjxxxxx4xxxxxx5aaabaaaxx
--no-ssl-verify --process-search-file="../test-file.txt"

------------------------------
Search Query | calc.exe
Resulting Processes | 6
Resulting Hosts | hostname_1 (100.0%)
------------------------------
Search Query | GRR
Resulting Processes | 8
Resulting Hosts | sc-31138 (62.5%)|gregorys-mbp (37.5%)
------------------------------
Search Query | lsass.exe
Resulting Processes | 17
Resulting Hosts | sc-31138 (47.1%)|gregorys-mbp (41.2%)|sc-31148 (11.8%)
'''

class cbConnect:
    'The cbConnect class is meant for connecting with\
    a Carbon Black server via the Carbon Black API'

    def __init__(self, cburl, apitoken, query=None):
            self.cburl = cburl
            self.apitoken = apitoken
            self.query = query

    def sensorConnect(self):
        cbConnection = cbapi.CbApi(self.cburl, token=self.apitoken, ssl_verify=False)
        return cbConnection

class printObjects:
    'A class for printing objects to console\
    which is meant for separating print statemnts\
    out of the primary code for CB server interaction'

    def __init__(self, cburl, testObject):
        self.testObject = testObject
        self.cburl = cburl

    def consolePrintTest(self):
        print"\n\n" + "Server: " + self.cburl
        print "-" * 80
        for key in self.testObject:
            print key


class cbDisplay:
    'The cbDisplay class is meant for pulling info from\
     a CB server using an active instance of the cbConnect\
     class'
    def __init__(self, cburl, cbConnection, query=None, procnamefile=None, sensorid=None):
        self.cbConnection=cbConnection
        self.cburl=cburl
        self.query=query
        self.connectionInfo=cbConnection.info()
        self.procnamefile=procnamefile
        self.sensorid=sensorid

    def returnServerInfo(self):
        'returns dictionary object containing basic server info'
        serverInfo = {}
        for key in self.connectionInfo.keys():
            serverInfo[key] = self.connectionInfo[key]
        return serverInfo

    def displayServerInfo(self):
        'print to console basic server info'
        for key in self.connectionInfo.keys():
            print "%-30s : %s" % (key, self.connectionInfo[key])

    def returnSensors(self):
        'returns dictionary object conatining all sensors along\
         with all attributes related to each sensor'
        sensorList = {}
        index = 0
        for key in self.cbConnection.sensors():
            for keys,values in key.items():
                sensorList[keys] = values
        return sensorList

    def returnSensorsIDs(self):
        'returns list object containing list of sensor IDs'
        sensors = self.cbConnection.sensors()
        slist = []
        for sensor in sensors:
            slist.append(sensor['id'])
        return slist

    def displaySensorsExtended(self):
        'prints to console a list of sensors with all related\
         attributes included'
        sensorList = {}
        index = 0
        for key in self.cbConnection.sensors():
            print "Computer Name: " + key['computer_name']
            print "-"*40
            for keys,values in key.items():
                sensorList[keys] = values
                print "%-30s : %s" % (keys,values)
            print "\n"

    def displaySensorsShort(self):
        'prints to console a list of sensors only with (status, \
         name, ID, Operating System & last checkin time)'

        sensors = self.cbConnection.sensors()
        print "::List of each Carbon Black Sensor::\n"
        for sensor in sensors:
            print "%-20s : %s" % ("computer name", sensor['computer_name'])
            print "-" * 80
            print "%-20s : %s" % ("sensor_group_id", sensor['group_id'])
            print "%-20s : %s" % ("sensor id", sensor['id'])
            print "%-20s : %s" % ("os", sensor['os_environment_display_string'])
            print "%-20s : %s" % ("last checkin time", sensor['last_checkin_time'])
            print "%-20s : %s" % ("status", sensor['status']) + "\n\n"

    def displaySensorDetails(self):
        'prints to console details of one sensor\
         requires sensor ID as argument for calling'

        print "::Detailed Info for each CB Sensor::\n"
        crap = self.cbConnection.sensor(self.sensorid)
        for key in crap.keys():
            print "%-35s : %s" % (key,crap[key])
    	print "\n\n"

    def processSearch(self):
        'prints to console - performing a process search from one argument'

        print "Process Search across CB server for query string: " + self.query
        print "-" * 80
        print "%s,%s,%s,%s,%s,%s" % ("hostname", "username", "start", "parent_path", "path", "cmdline")
        for (proc, proc_details, parent_details) in \
                self.cbConnection.process_search_and_detail_iter(self.query):

                print "%s,%s,%s,%s,%s,%s" % (proc.get('hostname'),
                                             proc.get('username'),
                                             proc.get('start'),
                                             parent_details.get('path'),
                                             proc.get('path'),
                                             proc_details.get('cmdline'))

    def binarySearch(self):
        'prints to console - conducting binary search from one argument'
        # perform a single binary search
        #
        binaries = self.cbConnection.binary_search(self.query)

        print "%-20s : %s" % ('Displayed Results', len(binaries['results']))
        print "%-20s : %s" % ('Total Results', binaries['total_results'])
        print "%-20s : %sms" % ('QTime', int(1000*binaries['elapsed']))
        print '\n'

        # for each result
        for binary in binaries['results']:
            print binary['md5']
            print "-" * 80
            print "%-20s : %s" % ('Size (bytes)', binary.get('orig_mod_len', '<UNKNOWN>'))
            print "%-20s : %s" % ('Signature Status', binary.get('digsig_result', '<UNKNOWN>'))
            print "%-20s : %s" % ('Publisher', binary.get('digsig_publisher', '<UNKNOWN>'))
            print "%-20s : %s" % ('Product Version', binary.get('product_version', '<UNKNOWN>'))
            print "%-20s : %s" % ('File Version', binary.get('file_version', '<UNKNOWN'))
            print "%-20s : %s" % ('64-bit (x64)', binary.get('is_64bit', '<UNKNOWN>'))
            print "%-20s : %s" % ('EXE', binary.get('is_executable_image', '<UNKNOWN>'))

            if len(binary.get('observed_filename', [])) > 0:
                print "%-20s : %s" % ('On-Disk Filename(s)', binary['observed_filename'][0].split('\\')[-1])
                for observed_filename in binary['observed_filename'][1:]:
                    print "%-20s : %s" % ('', observed_filename.split('\\')[-1])

            print '\n'

    def processSearchList(self):
        'returns list object containing lines of file stripped\
         cleaning up a file for use with ProcessSearchFile method'
        with open(self.procnamefile) as tmp:
            lines = filter(None, [line.strip() for line in tmp])
        return lines

    def processSearchFile(self, searchprocess):
        'prints to console - conducting a process search \
         from a file of queries. Accepts as argument the list of\
         lines produced from processSearchList() method'

        for search in searchprocess:
            data = self.cbConnection.process_search(search, rows=1)
            if 0 != (data['total_results']):
                print "------------------------------"
                print "Search Query | %s" % (search)
                print "Resulting Processes | %s" % (data['total_results'])
                facet=data['facets']
                hosts =[]
                for term in facet['hostname']:
                    hosts.append("%s (%s%%)" % (term['name'], term['ratio']))
                print "Resulting Hosts | "+"|".join(hosts)

    def hostStatus(self, hosts, system):
        'prints to console whether host is online/offline and returns ID\
         of system is the system is onine'

        hostList = hosts
        for host in hostList:
            crap = self.cbConnection.sensor(host)
            if crap['computer_name'] == system:
                if crap['status'] == 'Online':
                    print crap['computer_name'],crap['id'],crap['status']
                    return crap['id']
                else:
                    print "host %s with sensor id: " % system + str(crap['id']) + " is currently offline"


    def LRcollection(self, host):
        'prints to console & Performs Live Response for a system- accepts\
         target hostname as argument. checks online status and if online\
         pushes collection script and attempts to execute lr.exe on host'

        lfile = 'lr.exe'
        rfile = 'C:\lr.exe'
        sensor_id = host
        lrh = LiveResponseHelper(self.cbConnection, sensor_id)
        lrh.start()


        print "[*] Attempting to upload file: %s" % lfile
        results = lrh.put_file(rfile, lfile)
        print "\n[+] Results:\n============"
        for i in results:
            print i + ' = ' + str(results[i])
        print "attempting to execute %s" % rfile


        print lrh.execute("C:\lr.exe -y -gm2")
        time.sleep(7)

        print "attempting to execute bat script"
        print lrh.execute("""C:\lr\\tr3-collect.bat SC-31148 C 4 AKIAI3RI4ODHYKG5NOBA LZ+x53B9gGUbbycvzg2fIgx63VI9/URO4ZXx+aXK p@ssw0rd""")

        for process in lrh.process_list():
            print process['pid']
            print process['command_line']
            print process['path']

        lrh.stop()

    def returnHashes(self):
        'return list object containing md5 hashes pulled from\
         team cymru malware hashes file'
        import json
        lists = []
        with open('hashes-cb.json') as rb:
            data = json.load(rb)

        for x in range(0,len(data["reports"])):
            iocs = data["reports"][x]["iocs"]
            for keys, values in iocs.items():
                for line in values:
                    lists.append(line)
        return lists



def build_cli_parser():
    parser = optparse.OptionParser(usage="%prog [options]", description="Interact with Carbon Black API")

    # for each supported output type, add an option
    #
    parser.add_option("-c", "--cburl", action="store", default=None, dest="server_url",
                      help="CB server's URL.  e.g., http://127.0.0.1 ")
    parser.add_option("-a", "--apitoken", action="store", default=None, dest="token",
                      help="API Token for Carbon Black server")
    parser.add_option("-n", "--no-ssl-verify", action="store_false", default=True, dest="ssl_verify",
                      help="Do not verify server SSL certificate.")
    parser.add_option("-p", "--process-search", action="store", default=False, dest="process_query",
                      help="Conduct process search")
    parser.add_option("-s", "--server-info", action="store_true", default=False, dest="server_info",
                      help="Show server info")
    parser.add_option("-b", "--binary-search", action="store", default=False, dest="binary_query",
                      help="Conduct binary search")
    parser.add_option("-f", "--process-search-file", action="store", default=False, dest="procsearchfile",
                      help="Conduct process search from file of queries")
    parser.add_option("-m", "--sensor-list", action="store_true", default=False, dest="sensorlist",
                      help="Display list of sensors only showing hostname, ID, OS, status & last checkin")
    parser.add_option("-S", "--sensor-list-extended", action="store_true", default=False, dest="sensorlistextended",
                      help="Display list of sensors with all related attributes included")
    parser.add_option("-d", "--sensor-details", action="store", default=False, dest="sensordetails",
                      help="Display extended information for one sensor given by sensor ID")
    parser.add_option("-l", "--live-response", action="store", default=False, dest="liveresponse",
                      help="Conduct live response if host is online")
    parser.add_option("-i", "--cymru-intel", action="store_true", default=False, dest="cymru",
                      help="scan cymru intel for matches on server")

    return parser

def main(argv):
    parser = build_cli_parser()
    opts, args = parser.parse_args(argv)
    if not opts.server_url or not opts.token:
      print "Missing required param; run with --help for usage"
      sys.exit(-1)

    # build a cbapi object\\connect to the cb server
    #
    cb1 = cbConnect(opts.server_url, opts.token).sensorConnect()

    if opts.process_query:
        cbDisplay(opts.server_url, cb1, query=opts.process_query).processSearch()
    if opts.sensorlist:
        cbDisplay(opts.server_url, cb1).displaySensorsShort()
    if opts.sensorlistextended:
        cbDisplay(opts.server_url, cb1).displaySensorsExtended()
    if opts.sensordetails:
        cbDisplay(opts.server_url, cb1, sensorid=opts.sensordetails).displaySensorDetails()
    if opts.server_info:
        cbDisplay(opts.server_url, cb1).displayServerInfo()
        cbDisplay(opts.server_url, cb1).returnServerInfo()
    if opts.binary_query:
        cbDisplay(opts.server_url, cb1, query=opts.binary_query).binarySearch()
    if opts.procsearchfile:
        searchprocess = cbDisplay(opts.server_url, cb1, procnamefile=opts.procsearchfile).processSearchList()
        cbDisplay(opts.server_url, cb1).processSearchFile(searchprocess)
    if opts.liveresponse:
        sensorList = cbDisplay(opts.server_url, cb1).returnSensorsIDs()
        currSystem = cbDisplay(opts.server_url, cb1).hostStatus(sensorList, opts.liveresponse)
        cbDisplay(opts.server_url, cb1).LRcollection(currSystem)
    if opts.cymru:
        searchList = cbDisplay(opts.server_url, cb1).returnHashes()
        cbDisplay(opts.server_url, cb1).processSearchFile(searchList)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
