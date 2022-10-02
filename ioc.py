import argparse
import os.path
import re
import requests
import pandas as pd
import sys
import datetime
from urllib3.exceptions import InsecureRequestWarning
import ipaddress
from cymruwhois import Client
import validators

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
base_url = 'https://otx.alienvault.com/api/v1/indicators/'
headers = {'X-OTX-API-KEY':'alienvault key'}


whitelistOrgs = ["google","amazon","microsoft"]


def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg



def CheckIocType(ioc):
    md5 = re.compile(r'\b[0-9a-fA-F]{32}\b')
    sha1 = re.compile(r'\b[0-9a-fA-F]{40}\b')
    sha256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
    if re.search(md5,ioc.IndicatorValue):
        return "FileMd5"
    elif re.search(sha1,ioc.IndicatorValue):
        return "FileSha1"
    elif re.search(sha256,ioc.IndicatorValue):
        return "FileSha256"
    elif re.search("^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$", ioc.IndicatorValue):
        return "IpAddress"
    elif re.search("^(?!-)[A-Za-z0-9-]+([\\-\\.]{1}[a-z0-9]+)*\\.[A-Za-z]{2,63}$",ioc.IndicatorValue):
        return "DomainName"
    elif re.search("((http|https)://)(www.)?[a-zA-Z0-9@:%._\-\\+~#?&//=]{1,256}\\.[a-z0-9]{1,6}\\b([-a-zA-Z0-9@:%._\-\\+~#?&//=]*)",ioc.IndicatorValue):
        return "Url"
    else :
        return "invalid"




def CheckReputation(ioc):

    if ioc.IndicatorType in ["FileMd5","FileSha1","FileSha256"]:
        iocType = "file"
    elif ioc.IndicatorType == "DomainName":
        iocType = "domain"
    elif ioc.IndicatorType == "Url":
        iocType = "url"
    elif ioc.IndicatorType == "IpAddress":
        iocType = "IPv4"
    else :
        return "NA"
    try:
        response = requests.get(base_url+iocType+'/'+ioc.IndicatorValue+'/general', headers=headers,verify=False).json()
        pulses = response['pulse_info']['count']
        print(ioc.IndicatorValue, "----\t",pulses)
        return pulses
    except Exception as e:
        print(ioc.IndicatorValue, "----\t",e)
        return "error"
 


def DefenderAction(ioc) :
    if ioc.IndicatorType in ["FileMd5","FileSha1","FileSha256"]:
        return "BlockAndRemediate"
    else :
        return "Block"

def IsWhiteListed(ip) :
    if ip.IndicatorType == "IpAddress" :
        for prefix in whitelistedIocs.Prefix:
            if ipaddress.ip_address(ip.IndicatorValue) in ipaddress.ip_network(prefix):
                return True
    return False



def CheckPort(ioc) :
    
    if len(ioc.IndicatorValue.rsplit(":",1)) >1 :
        if ioc.IndicatorValue.rsplit(":",1)[1].isnumeric():
            return ioc['IndicatorValue'].rsplit(":",1)[0]
    return ioc['IndicatorValue']



parser = argparse.ArgumentParser(description='Convert a list of IOCs to csv files accepted by Defender, Carbon Black Defence and Darktrace. For input file each line must contain only one IOC')
parser.add_argument("-i", dest="iocFile", required=True,
                    help="input file with iocs delimited by newline", metavar="FILENAME",
                    type=lambda x: is_valid_file(parser, x))
parser.add_argument("-l", dest="lookupFile", required=False,
                    help="IOC list from defender to find duplicates", metavar="FILENAME",
                    type=lambda x: is_valid_file(parser, x),nargs='*')
parser.add_argument("-w", dest="whitelistFile", required=False,
                    help="input csv file containing the whitelisted ip prefixes", metavar="FILENAME",
                    type=lambda x: is_valid_file(parser, x))
parser.add_argument('--no-check', dest = 'ipCheck', help="disable ip check for whiteslisting",const=False, action='store_const', default=True)
parser.add_argument('-title', dest = 'title', help="threat advisory name", type=str,required=True)

args = parser.parse_args()
iocs=pd.read_csv(args.iocFile, header=None, names=["IndicatorValue"])
    


iocs['IndicatorValue'] = iocs['IndicatorValue'].str.lower()
iocs['IndicatorValue'] = iocs['IndicatorValue'].str.strip()
iocs['IndicatorValue'] = iocs['IndicatorValue'].str.replace(' ','',regex=True)
iocs['IndicatorValue'] = iocs['IndicatorValue'].str.replace('[','',regex=True)
iocs['IndicatorValue'] = iocs['IndicatorValue'].str.replace(']','',regex=True)
iocs['IndicatorValue'] = iocs['IndicatorValue'].str.replace('hxxps://','https://',regex=True)
iocs['IndicatorValue'] = iocs['IndicatorValue'].str.replace('hxxp://','http://',regex=True)
iocs['IndicatorValue'] = iocs.apply (lambda row: CheckPort(row), axis=1)
TotalNoOfIocs = len(iocs)
iocs = iocs.drop_duplicates()


iocs['IndicatorType'] = iocs.apply (lambda row: CheckIocType(row), axis=1)
iocs['Reason'] = "NA"

iocs.loc[iocs.IndicatorType =="invalid",['Reason']] = "Error parsing IOC"

iocs['Implemented'] = False


if args.lookupFile is not None:
    implementedIocs = pd.concat((pd.read_csv(f) for f in args.lookupFile))
    iocs = iocs.assign(Implemented=iocs['IndicatorValue'].isin(implementedIocs['IndicatorValue']).astype(bool))


iocs['Whitelisted'] = False
if args.whitelistFile is not None:
    whitelistedIocs = pd.read_csv(args.whitelistFile)
    iocs['Whitelisted'] = iocs.apply (lambda row: IsWhiteListed(row), axis=1)
    iocs.loc[iocs.Whitelisted == True,['Reason']] = "Whitelisted as per given list"






if args.ipCheck == True:
    try:
        ipsInfo = Client().lookupmany(iocs[iocs.IndicatorType=="IpAddress"].IndicatorValue.tolist())
    except :
        print("\nwarning -- error occured while fetching ip details from web")
    else :
        whitelistedIps = pd.DataFrame(columns=['ip','org'])
        for ipInfo in ipsInfo:
            if any(org.lower() in ipInfo.owner.lower() for org in whitelistOrgs):
                whitelistedIps.loc[len(whitelistedIps.index)] = [ipInfo.ip,ipInfo.owner]
        if len(whitelistedIps) : 
            iocs = iocs.assign(Whitelisted=iocs['IndicatorValue'].isin(whitelistedIps.ip).astype(bool))
            for index,ip in whitelistedIps.iterrows():
                iocs.loc[iocs.IndicatorValue == ip.ip,['Reason']] = "Whitelisted as per "+ip.org

#iocs['Reputation'] = iocs.apply (lambda row: CheckReputation(row), axis=1)

error  = iocs[['IndicatorValue','Reason']][(iocs.IndicatorType== "invalid") | (iocs.Implemented == True ) | (iocs.Whitelisted == True)]
if len(error):
    error.to_csv('Excluded_IOCs_'+ args.title+str(datetime.datetime.now().day)+ datetime.datetime.now().strftime("%B") + str(datetime.datetime.now().year)+'.csv',index=False)


Defender = iocs[['IndicatorType','IndicatorValue']][((iocs.IndicatorType != "invalid") & (iocs.Implemented == False ) & (iocs.Whitelisted == False))]
if len(Defender):
    Defender['ExpirationTime'] = ""
    Defender['Action'] = iocs.apply (lambda row: DefenderAction(row), axis=1)
    Defender['Severity'] = "High"
    Defender['Title'] = "Blacklisted IOC from Threat Advistory - "+ args.title + " " + str(datetime.datetime.now().day)+" " + datetime.datetime.now().strftime("%B")+ " " + str(datetime.datetime.now().year)
    Defender['Description'] = "IOCs for Threat Advisory - "+ args.title + " "  + str(datetime.datetime.now().day)+" " + datetime.datetime.now().strftime("%B")+ " " + str(datetime.datetime.now().year)
    Defender['RecommendedActions'] = "Isolate the machine, raise an incident  and take the system out of the network"
    Defender['Scope/DeviceGroups'] = ""
    Defender['Category'] = "Discovery"
    Defender['MitreTechniques'] = ""
    Defender['GenerateAlert'] = "TRUE"
    Defender.to_csv('Defender_IOCs_'+ args.title+str(datetime.datetime.now().day)+ datetime.datetime.now().strftime("%B") + str(datetime.datetime.now().year)+'.csv',index=False)



 



CBD = iocs[['IndicatorValue']][(iocs.IndicatorType == "FileSha256") & (iocs.IndicatorType != "invalid") & (iocs.Implemented == False ) & (iocs.Whitelisted == False)]
if len(CBD):
    CBD.insert(0,'Action','BLACK_LIST')
    CBD.insert(1,'IndicatorType','SHA256')
    CBD.insert(3,'Descripton',"Blacklisted IOC from Threat Advistory - "+ args.title + " "  + str(datetime.datetime.now().day)+" " + datetime.datetime.now().strftime("%B")+ " " + str(datetime.datetime.now().year))
    CBD.insert(4,'ApplicationName','Generic')
    CBD.to_csv('CBD_IOCs_'+ args.title+str(datetime.datetime.now().day)+ datetime.datetime.now().strftime("%B") + str(datetime.datetime.now().year)+'.csv',index=False,header=False)





DT = iocs[['IndicatorValue']][((iocs.IndicatorType == "IpAddress") | (iocs.IndicatorType == "DomainName")) & (iocs.IndicatorType != "invalid") & (iocs.Implemented == False ) & (iocs.Whitelisted == False)].rename(columns={'IndicatorValue': 'domain'})
if len(DT):
    DT['exact host'] = ""
    DT['description'] = "Blacklisted IOC from Threat Advistory - "+ args.title + " "  + str(datetime.datetime.now().day)+" " + datetime.datetime.now().strftime("%B")+ " " + str(datetime.datetime.now().year)
    DT['strength'] = "100"
    DT['source'] = "default"
    DT['expiry'] = ""
    DT['iagn'] = "yes"
    DT.to_csv('Darktrace_IOCs_'+ args.title +str(datetime.datetime.now().day)+ datetime.datetime.now().strftime("%B") + str(datetime.datetime.now().year)+'.csv',index=False)


NoOfDuplicates = TotalNoOfIocs - len(iocs)
NoOfImplementedIocs = len(iocs[iocs["Implemented"] == True].index)
NoOfInvalidIocs = len(iocs[iocs["IndicatorType"] == "invalid"].index)
NoOfWhitelistedIocs = len(iocs[iocs["Whitelisted"] == True].index)
NoOfDTIocs = len(DT)
NoOfDefenderIocs = len(Defender)
NoOfCBDIocs = len(CBD)

print("\nNo Of IOCs submitted : ", TotalNoOfIocs)

print("\nNo Of IOCs generated : ", TotalNoOfIocs - NoOfDuplicates - NoOfImplementedIocs - NoOfInvalidIocs - NoOfWhitelistedIocs,"\t||",end="\t")
print("DT : ", NoOfDTIocs,end="")
print(", Defender : ", NoOfDefenderIocs,end="")
print(", CBD : ", NoOfCBDIocs)

print("\nNo of IOCs already implemented : ", NoOfImplementedIocs)
print("No of IOCs got error while parsing : ",NoOfInvalidIocs)
print("No Of duplicates : ", NoOfDuplicates)
print("No Of IOCs whitelisted : ",NoOfWhitelistedIocs,"\n")




iocs['IndicatorValue'][((iocs.IndicatorType != "invalid") & (iocs.Implemented == False ) & (iocs.Whitelisted == False))].to_csv('All_IOCs_'+ args.title +str(datetime.datetime.now().day)+ datetime.datetime.now().strftime("%B") + str(datetime.datetime.now().year)+'.csv',index=False,header=False)
