'''-----------------------------------------------------------------------------------------
 
 CS39006: Networks Laboratory
 Assignment 2: Packet Sniffer and Packet Analyzer -- Exploring Further
 Learning tshark and writing scripts to analyze pcap

 Name     : Abhinav Bohra
 Roll No. : 18CS30049

------------------------------------------------------------------------------------------'''

'''******************************************************************************************

 Instructions for Use:

 1. Install GeoLite2 using the command -> pip install maxminddb-geolite2
 2. Say, the xml file name is http.xml, then run : >> python A2_18CS30049_parse.py http.xml
 3. The output is written in data.csv in the same directory as that of python source file

******************************************************************************************'''

'''------------------------------------------------------------------------------------------
 STEP 1 : Importing important Libraries
 ------------------------------------------------------------------------------------------'''
#Library to pare XML file -> 'http.xml'
from xml.etree import ElementTree
#Library to get country name from IP Address (installed using -> pip install maxminddb-geolite2)
from geolite2 import geolite2 
#Library to convert country code to country name
import csv
#Library to input filename from terminal as argument
import sys


'''------------------------------------------------------------------------------------------
 STEP 2 : Parsing XML File -> 'http.xml' into python object 
------------------------------------------------------------------------------------------'''
#Takes input filename from terminal as argument
filename = sys.argv[1]
#Stores data into dom (dtype :xml.etree.ElementTree.ElementTree)
dom = ElementTree.parse(filename)
#Root element of XML Tree
root = dom.getroot()
#Filters Packets with Proto name = 'http'  
protos = root.findall("packet/proto[@name='http']") 


'''------------------------------------------------------------------------------------------
 STEP 3 : Find IP address of original user who has accessed service via Internet.org proxy
------------------------------------------------------------------------------------------'''
# List/Array to store IP addresses
IPList = list()

for proto in protos:
    temp_IP=0    
    #Traverse all fields in proto 
    for field in proto.iterfind('field'):
        #Temporarily Save IP address of packet if field name is 'http.x_forwarded_for'
        if(field.attrib['name'] == 'http.x_forwarded_for'):
            temp_IP = field.attrib['show']
            break
            
    #Traverse all fields in proto         
    for field in proto.iterfind('field'):
        #Save IP address only if user has accessed the service via the Internet.org proxy
        if(field.attrib['name']=='http.request.line' and field.get('showname') == "Via: Internet.org\\r\\n"):
            IPList.append(temp_IP)
            break
            
            
'''------------------------------------------------------------------------------------------
 STEP 4 : Find country from IP & Calculate Frequency of each country
------------------------------------------------------------------------------------------'''
#Consider only 'Unique' IP addresses
IPList = set(IPList)

# List/Array to store country names
countries = list()

for IP in IPList:
    #Fetch Country Name from each IP address
    country = (geolite2.reader().get(IP))['country']['names']['en']
    #Store it in countries list
    countries.append(country.upper())
    
#Calculate Frequency of each country
output = dict((x,countries.count(x)) for x in set(countries))
#Sort them in ascending order by count
output = dict(sorted(output.items(), key=lambda item: item[1]))


'''------------------------------------------------------------------------------------------
 STEP 5 : Save Country Name & corresponding counts in 'data.csv' file
------------------------------------------------------------------------------------------'''
with open('data.csv', 'w') as csv_file:
    writer = csv.writer(csv_file)
    for key, value in output.items():
        writer.writerow([key, value])
    print("\n\nProgram Executed Successfully.")
    print(len(IPList), "unique IPs found.")
    print(len(set(countries)), "countries reported.")
    print("For more details please check 'data.csv' file.\n\n")