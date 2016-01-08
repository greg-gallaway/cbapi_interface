import cbapi
import sys
import struct
import socket
import json
import optparse

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


class cbDisplay:
    'The cbDisplay class is meant for pulling info from\
     a CB server using an active instance of the cbConnect\
     class'
    def __init__(self, cburl, cbConnection, query=None, procnamefile=None):
        self.cbConnection=cbConnection
        self.cburl=cburl
        self.query=query
        self.connectionInfo=cbConnection.info()
        self.procnamefile=procnamefile

    def displayServerInfo(self):
        print "\n\n" + "Server: " + self.cburl
        print "-" * 80
        keylist = []
        for key in self.connectionInfo.keys():
            print "%-30s : %s" % (key, self.connectionInfo[key])
            keylist.append("%-30s : %s" % (key, self.connectionInfo[key]))
        return keylist

    def displaySensors(self):
        sensors = cbConnection.sensors()
        slist = []
        print "::List of each Carbon Black Sensor::\n"
        for sensor in sensors:
            print "%-20s : %s" % ("computer name", sensor['computer_name'])
            print "-" * 80
            print "%-20s : %s" % ("sensor_group_id", sensor['group_id'])
            print "%-20s : %s" % ("sensor id", sensor['id'])
            print "%-20s : %s" % ("os", sensor['os_environment_display_string'])
            print "%-20s : %s" % ("last checkin time", sensor['last_checkin_time']) + "\n\n"
            slist.append(sensor['id'])
        return slist

    def displaySensorDetails(self, sensorid):
        sensorInfos = []
        print "::Detailed Info for each CB Sensor::\n"
        for id in sensorid:
            crap = cbConnection.sensor(id)
            for key in crap.keys():
                print "%-35s : %s" % (key,crap[key])
    	print "\n\n"

    def processSearch(self):
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
        with open(self.procnamefile) as tmp:
            lines = filter(None, [line.strip() for line in tmp])
        return lines

    def processSearchFile(self, searchprocess):
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
    if opts.server_info:
        cbDisplay(opts.server_url, cb1).displayServerInfo()
    if opts.binary_query:
        cbDisplay(opts.server_url, cb1, query=opts.binary_query).binarySearch()
    if opts.procsearchfile:
        searchprocess = cbDisplay(opts.server_url, cb1, procnamefile=opts.procsearchfile).processSearchList()
        cbDisplay(opts.server_url, cb1).processSearchFile(searchprocess)



if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
