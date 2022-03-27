import argparse
from math import degrees
import os.path
import re
from socket import dup
from urllib.parse import urlparse
import requests
import pandas as pd
import sys
import datetime

base_url = 'https://otx.alienvault.com/api/v1/indicators/'
headers = {'X-OTX-API-KEY':'<key>'}


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
    elif re.search("((http|https)://)(www.)?[a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)",ioc.IndicatorValue):
        return "Url"
    elif re.search("^(?!-)[A-Za-z0-9-]+([\\-\\.]{1}[a-z0-9]+)*\\.[A-Za-z]{2,6}$",ioc.IndicatorValue):
        return "DomainName"
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
        response = requests.get(base_url+iocType+'/'+ioc.IndicatorValue+'/general', headers=headers).json()
        pulses = response['pulse_info']['count']
        print(ioc.IndicatorValue, "----\t",pulses)
        return pulses
    except:
        print(ioc.IndicatorValue, "----\t","error")
        return "error"
 


def DefenderAction(ioc) :
    if ioc.IndicatorType in ["FileMd5","FileSha1","FileSha256"]:
        return "BlockAndRemediate"
    else :
        return "Block"





parser = argparse.ArgumentParser(description='Convert a list of IOCs to csv files accepted by Defender, Carbon Black Defence and Darktrace. For input file each line must contain only one IOC')
parser.add_argument("-i", dest="iocFile", required=True,
                    help="input file with iocs delimited by newline", metavar="FILENAME",
                    type=lambda x: is_valid_file(parser, x))
parser.add_argument("-l", dest="lookupFile", required=False,
                    help="IOC list from defender to find duplicates", metavar="FILENAME",
                    type=lambda x: is_valid_file(parser, x))

args = parser.parse_args()
iocs=pd.read_csv(args.iocFile, sep="\n", header=None, names=["IndicatorValue"])


iocs['IndicatorValue'] = iocs['IndicatorValue'].str.strip()
iocs['IndicatorValue'] = iocs['IndicatorValue'].str.replace(' ','',regex=True)
iocs['IndicatorValue'] = iocs['IndicatorValue'].str.replace('[','',regex=True)
iocs['IndicatorValue'] = iocs['IndicatorValue'].str.replace(']','',regex=True)


iocs['IndicatorType'] = iocs.apply (lambda row: CheckIocType(row), axis=1)





if "invalid" in iocs.IndicatorType.values:
    print("\nSome error occured while parsing %s IOC(s) : \n\n" %NoOfInvalidIocs,*iocs[iocs.IndicatorType == "invalid"].IndicatorValue.values,"\n",sep='\n')
    userInput = ""
    while True:
        userInput = input('Do you want to continue? (y/n) : ')
        if len(userInput) == 1:
            break
        print("Please enter y or n")
    if userInput.lower() != 'y' :
        sys.exit("")


iocs['Implemented']= False

if args.lookupFile is not None:
    implementedIocs = pd.read_csv(args.lookupFile)
    iocs = iocs.assign(Implemented=iocs['IndicatorValue'].isin(implementedIocs['IndicatorValue']).astype(bool))





iocs['Reputation'] = iocs.apply (lambda row: CheckReputation(row), axis=1)



iocs.to_csv('iocs.csv',index=False)


Defender = iocs[['IndicatorType','IndicatorValue']][iocs.Implemented==False]
Defender['ExpirationTime'] = ""
Defender['Action'] = iocs.apply (lambda row: DefenderAction(row), axis=1)
Defender['Severity'] = "High"
Defender['Title'] = "Blacklisted IOC from Threat Advistory " + str(datetime.datetime.now().day)+" " + datetime.datetime.now().strftime("%B")+ " " + str(datetime.datetime.now().year)
Defender['Description'] = "" 
Defender['RecommendedActions'] = ""
Defender['Scope/DeviceGroups'] = ""
Defender['Category'] = ""
Defender['MitreTechniques'] = ""
Defender['GenerateAlert'] = ""
Defender.to_csv('defender.csv',index=False)



 



CBD = iocs[['IndicatorValue']][(iocs.IndicatorType == "FileSha256") & (iocs.Implemented==False)]
CBD.insert(0,'Action','BLACK_LIST')
CBD.insert(1,'IndicatorType','SHA256')
CBD.insert(3,'Descripton',"Blacklisted IOC from Threat Advistory " + str(datetime.datetime.now().day)+" " + datetime.datetime.now().strftime("%B")+ " " + str(datetime.datetime.now().year))
CBD.insert(4,'ApplicationName','Generic')
CBD.to_csv('cbd.csv',index=False,header=False)




DT = iocs[['IndicatorValue']][(iocs.IndicatorType == "IpAddress") | (iocs.IndicatorType == "DomainName") & (iocs.Implemented==False)].rename(columns={'IndicatorValue': 'domain'})
DT['exact host'] = ""
DT['description'] = "Blacklisted IOC from Threat Advistory " + str(datetime.datetime.now().day)+" " + datetime.datetime.now().strftime("%B")+ " " + str(datetime.datetime.now().year)
DT['strength'] = "100"
DT['source'] = "default\\r"
DT['expiry'] = ""
DT['iagn'] = "yes"
DT.to_csv('dt.csv',index=False)



TotalNoOfIocs = len(iocs)
NoOfInvalidIocs = len(iocs[iocs["IndicatorType"] == "invalid"].index)
NoOfImplementedIocs = len(iocs[iocs["Implemented"] == True].index)

print("Total No Of IOCs : ", TotalNoOfIocs)
print("No Of Implemented : ", NoOfImplementedIocs)
print("No of invalid : ",NoOfInvalidIocs)