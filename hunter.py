'''

Threat Hunter Code

'''
import datetime
import requests
from OTXv2 import OTXv2
from tinydb import TinyDB, Query

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.

# Use my OTX API Key
otx = OTXv2("YOUR_APKI_KEY")

# Use my XFE API Key
auth_header = {'authorization': 'Basic \
YOUR_API_KEY_BASE64'}

# XFE IP Reputation URL
IPReputationURL = "https://api.xforce.ibmcloud.com/api/ipr/"
#URLReputationURL = "https://exchange.xforce.ibmcloud.com/url/honeyminer.live"

# abuse.ch
abuse_dot_ch_URL = "https://threatfox-api.abuse.ch/api/v1/"

# SANS Internet Storm Center
#   https://isc.sans.edu/api/ip/64.62.197.53?json
SANS_ISC_URL = "https://isc.sans.edu/api/ip/"

# Setup the DB:
my_database = TinyDB('my_database.json')
updateIOC = Query()


def main():

    Industry, start_date = readConfig()
    date_fields = start_date.split('-')
    IP_List = []

    industryPulses = retrieveIndustryPulses(Industry)

    trustedPulses = getTrustedPulses(industryPulses)

    print("Number of industry related entries: " + str(industryPulses['count']))

    for iterate_pulse in trustedPulses:

        currentPulse = otx.get_pulse_details(iterate_pulse['id'])

        for currentIndicator in currentPulse['indicators']:
            if currentIndicator['type'] == "IPv4":
                creationDateComponents = currentIndicator["created"].split('T')[0].split('-')
                creationDate = datetime.date(int(creationDateComponents[0]), \
                        int(creationDateComponents[1]), int(creationDateComponents[2]))
                if creationDate >= datetime.date(int(date_fields[0]), \
                        int(date_fields[1]), int(date_fields[2])):
                    if currentIndicator['indicator'] not in IP_List:
                        IP_List.append(currentIndicator['indicator'])
                        my_database.insert({'type': 'IPv4', 'value': \
                        currentIndicator['indicator'], 'threat-actor': currentPulse['adversary']})

    print("Number of IOCs before cross-checking with different CTI feeds: "+ str(len(IP_List)))

    IOC_List = {}
    for eachIP in IP_List:
        finalScore = 0
        myURL = IPReputationURL + eachIP
        XFE_Response = requests.get(myURL, headers=auth_header)
        XFE_Result = XFE_Response.json()
        if XFE_Result["score"] != 1:
            IOC_List[eachIP] = XFE_Result["score"]
            finalScore += XFE_Result["score"]
            my_database.update({"XFE_Score": XFE_Result["score"]}, updateIOC.value == eachIP)
        else:
            IOC_List[eachIP] = 0
            my_database.update({"XFE_Score": 0}, updateIOC.value == eachIP)

        # SANS ISC
        mySANS_ISC_URL = SANS_ISC_URL + eachIP + "?json"
        SANS_ISC_Response = requests.get(mySANS_ISC_URL)
        SANS_ISC_Result = SANS_ISC_Response.json()

        # abuse.ch
        abuseCH_query = {"query": "search_ioc", "search_term": eachIP }
        abuseCH_Response = requests.post(abuse_dot_ch_URL, json=abuseCH_query)
        abuseCH_Result = abuseCH_Response.json()

        print(eachIP + "\n" + "XFE Score:\t" + str(XFE_Result["score"]))
        if abuseCH_Result["query_status"] == "no_result":
            print("abuse.ch Score:\tN/A")
            my_database.update({"abuseCH_Score": 0}, updateIOC.value == eachIP)
        else:
            print("abuse.ch Score:\t" + str(abuseCH_Result["data"][0]["confidence_level"]/10))
            my_database.update({"abuseCH_Score": abuseCH_Result["data"][0]["confidence_level"]/10}\
                               , updateIOC.value == eachIP)
            finalScore += abuseCH_Result["data"][0]["confidence_level"]/10
        print("SANS ISC status: " + str(SANS_ISC_Result["ip"]["attacks"]))
        if str(SANS_ISC_Result["ip"]["attacks"]) != "None":
            my_database.update({"SANS_ISC_Score": SANS_ISC_Result["ip"]["attacks"]/100},\
                               updateIOC.value == eachIP)
            finalScore += SANS_ISC_Result["ip"]["attacks"]/100
            if finalScore > 10:
                finalScore = 10
            my_database.update({"Overall": finalScore}, updateIOC.value == eachIP)
        else:
            my_database.update({"SANS_ISC_Score": 0}, updateIOC.value == eachIP)
            if finalScore > 10:
                finalScore = 10
            my_database.update({"Overall": finalScore}, updateIOC.value == eachIP)

    Final_IOC_List = []
    for eachIOC in IOC_List:
        if IOC_List[eachIOC] > 5:
            Final_IOC_List.append(eachIOC)

    print("Database records:")
    for record in my_database:
        if record["Overall"] > 1:
            print(record["value"])

def retrieveIndustryPulses(qIndustry):
    industryPulses = otx.search_pulses("industry:"+qIndustry, max_results=500)
    return industryPulses

def getTrustedPulses(industryPulses):
    trustedPulses = []
    for iterate_pulse in industryPulses['results']:
        #if iterate_pulse['author_name'] == "AlienVault":
        if iterate_pulse['author_name']:
            #print(iterate_pulse)
            trustedPulses.append(iterate_pulse)
    return trustedPulses

def readConfig():
    configuredIndustry = ""
    configured_start_date = ""
    with open("hunter_config.txt") as configFile:
        for currentLine in configFile:
            if currentLine.strip() == "#INDUSTRY":
                configuredIndustry =  configFile.readline()
            if currentLine.strip() == "#STARTDATE":
                configured_start_date = configFile.readline()
        return configuredIndustry.strip(), configured_start_date.strip()


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
