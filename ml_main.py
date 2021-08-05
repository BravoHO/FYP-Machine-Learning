import tensorflow as tf
from tensorflow import keras
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import copy
from datetime import date
import json
import csv
import os
from sklearn.preprocessing import StandardScaler
import plotly.graph_objects as go
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM, Dropout, RepeatVector, TimeDistributed
from keras.models import load_model
model1 = load_model('ML_model.h5')
pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)

df = pd.read_csv('0.csv')

#filter tags and count tags

print("Tags") #to alert when it has reached tags
desc = df['Tags']
prearr = ""
for index, row in df.iterrows():
  prearr+=str(row['Tags'])
  prearr+=';'
prearr = prearr.split(";")
prearr2 = list(set(prearr))
tagcount = dict.fromkeys(prearr2,0)

for i in prearr:
  tagcount[i]+=1

#output for maltego (tag frequency)

col1 = []
col2 = []

for i in tagcount:
  col1.append(i)
  col2.append(tagcount[i])

data = {'col_1': col1, 'col_2': col2}
datadf = pd.DataFrame.from_dict(data)
datadf = datadf.sort_values(by=['col_2'], ascending=False)
datadf.to_csv('Trending_Tags_old.csv')

#filter countries in asia USA and Russia
print("Countries")
asia = ['Afghanistan', 'Armenia', 'Azerbaijan', 'Bahrain', 'Bangladesh', 'Bhutan', 'British Indian Ocean Territory', 'Brunei', 'Cambodia', 'China', 'Christmas Island', 'Cocos Islands', 'Georgia', 'Hong Kong', 'India', 'Indonesia', 'Iran', 'Iraq', 'Israel', 'Japan', 'Jordan', 'Kazakhstan', 'Kuwait', 'Kyrgyzstan', 'Laos', 'Lebanon', 'Macau', 'Malaysia', 'Maldives', 'Mongolia', 'Myanmar', 'Nepal', 'North Korea', 'Oman', 'Pakistan', 'Palestine', 'Philippines', 'Qatar', 'Saudi Arabia', 'Singapore', 'South Korea', 'Sri Lanka', 'Syria', 'Taiwan', 'Tajikistan', 'Thailand', 'Turkey', 'Turkmenistan', 'United Arab Emirates', 'Uzbekistan', 'Vietnam', 'Yemen', 'Russia', 'United States']
for i in range(len(asia)):
  asia[i] = asia[i].lower()

country_tags = dict.fromkeys(asia, 0)

for i in tagcount:
  if i.lower() in asia:
    country_tags[i.lower()] = tagcount[i]

#count threat score for each country
country_details = {'Host': 0, 'URL': 0, 'Address': 0, 'File': 0, 'CIDR': 0, 'ASN': 0, 'EmailAddress': 0}
country_score = {}
for i in country_tags:
  country_score[i] = 0
for i in country_score:
  country_score[i] = 0

country_detail = {}
for i in country_score:
  country_detail[i] = country_details.copy()

score = df['Rating']
desc = df['Tags']

df['Rating'] = df['Rating'].fillna(0)

counter2 = 0
for index, row in df.iterrows():
  a = str(row['Tags'])
  a = a.split(";")
  b = row['Type']
  for i in a:
    if i.lower() in country_score:
      country_score[i.lower()]+=int(row['Rating'])
      country_detail[i.lower()][b]+=1
  counter2+=1
print("Owners")
#get source owners, count mentions and score
source_owners = ['System', 'ThreatConnect Intelligence', 'Firebog Prigent Phishing Domains', 'hpHosts Malware Distribution Domains', 'abuse.ch Zeus Tracker', 'hpHosts Phishing Domains', 'hpHosts Exploit Domains', 'abuse.ch URLHaus', 'dan.me Tor Exit Nodes', 'abuse.ch TorrentLocker Ransomware C2 Domain Blocklist', 'WSTNPHX Malware Email Addresses', 'abuse.ch TeslaCrypt Ransomware C2 Domain Blocklist', 'abuse.ch Ransomware Tracker', 'abuse.ch Ransomware Domain Blocklist', 'abuse.ch Locky Ransomware C2 Domain Blocklist', 'abuse.ch CryptoWall Ransomware C2 Domain Blocklist', 'abuse.ch Feodo Tracker', 'VXVault', 'StopForumSpam Toxic CIDRs', 'SARVAM', 'PhishTank', 'OpenPhish', 'Rutgers Attacker IPs', 'PDFExaminer', 'Minotaur URLs', 'Manwe Mac Malware', 'Firebog Shalla Malware Domains', 'Malware Domain Blocklist', 'MalShare Daily Malware List', 'MalwareConfig', 'Maldun Malware Analysis', 'Haley SSH Bruteforce IPs', 'Hybrid Analysis', 'Cert-pa.it Latest Malware Analysis', 'MITRE ATT&CK', 'GreenSnow Blocklist', 'Cryptam', 'Firebog Prigent Malware Domains', 'Cybercrime Tracker', 'Firebog Airelle Hrsk Domains', 'DShield.org Recommended Blocklist CIDRs', 'Disconnect.me Malvertising', 'Cedia.org.ec Immortal Domains', 'CINS Army IP List', 'CAL Suspected Ranking Manipulators', 'CAL Suspected DGA NRDs', 'CAL Retail-themed NRDs', 'CAL Manufacturing-themed NRDs', 'CAL Finance-themed NRDs', 'Blocklist.de IMAP IPs', 'CAL Energy-themed NRDs', 'CAL Communications-themed NRDs', 'CAL COVID19-themed Newly Registered Domains', 'BruteForceBlocker Blocklist', 'Botvrij IPs', 'Blocklist.de FTP IPs', 'Botvrij Domains', 'Blocklist.de Bruteforce IPs', 'BotScout Bot List', 'Blocklist.de Strong IPs', 'CAL Suspicious Nameservers', 'CAL Suspicious New Resolution IPs', 'CAL Suspicious Newly Registered Domains', 'Blocklist.de Bot IPs', 'Blocklist.de Apache IPs', 'Blocklist.de SSH IPs', 'Blocklist.de SIP IPs', 'Blocklist.de Mail IPs', 'Bambenek']

source_owners_count = dict.fromkeys(source_owners, 0)
source_owners_score = dict.fromkeys(source_owners, 0)

counter3 = 0
for index, row in df.iterrows():
  a = row['Organization']
  source_owners_count[a]+=1
  source_owners_score[a]+=int(row['Rating'])
  counter3+=1


#count source owner type
categoriesss = {'Host': 0, 'URL': 0, 'Address': 0, 'File': 0, 'CIDR': 0, 'ASN': 0, 'EmailAddress': 0}
source_owner_category = {}
for i in source_owners:
  source_owner_category[i] = categoriesss.copy()


for index, row in df.iterrows():
  a = row['Organization']
  b = row['Type']
  source_owner_category[a][b]+=1


f1 = open('Owner_ML.json',)
f = open('Country_ML.json',)
data_country = json.load(f)
data_owner = json.load(f1)

datetoday = date.today()
for i in data_country:
  data_country[i]["Mentions"].append(country_tags[i])
  data_country[i]["Score"].append(country_score[i])
  data_country[i]["Host"].append(country_detail[i]["Host"])
  data_country[i]["URL"].append(country_detail[i]["URL"])
  data_country[i]["Address"].append(country_detail[i]["Address"])
  data_country[i]["File"].append(country_detail[i]["File"])
  data_country[i]["CIDR"].append(country_detail[i]["CIDR"])
  data_country[i]["ASN"].append(country_detail[i]["ASN"])
  data_country[i]["Email"].append(country_detail[i]["EmailAddress"])
  data_country[i]["Date"].append(str(datetoday))
for i in data_owner:
  data_owner[i]["Mentions"].append(source_owners_count[i])
  data_owner[i]["Score"].append(source_owners_score[i])
  data_owner[i]["Host"].append(source_owner_category[i]["Host"])
  data_owner[i]["URL"].append(source_owner_category[i]["URL"])
  data_owner[i]["Address"].append(source_owner_category[i]["Address"])
  data_owner[i]["File"].append(source_owner_category[i]["File"])
  data_owner[i]["CIDR"].append(source_owner_category[i]["CIDR"])
  data_owner[i]["ASN"].append(source_owner_category[i]["ASN"])
  data_owner[i]["Email"].append(source_owner_category[i]["EmailAddress"])
  data_owner[i]["Date"].append(str(datetoday))

print("ML")
def return_anomalies(arr):
  arr2 = []
  for i in range(len(arr)):
      arr2.append(i)
  df = pd.DataFrame(list(zip(arr2,arr)), columns = ["Day","Frequency"])
  #print(df)
  test = df.loc[df['Day'] > -1]

  scaler = StandardScaler()
  scaler = scaler.fit(np.array(test['Frequency']).reshape(-1,1))

  test['Frequency'] = scaler.transform(np.array(test['Frequency']).reshape(-1,1))

  TIME_STEPS=1

  def create_sequences(X, y, time_steps=TIME_STEPS):
      X_out, y_out = [], []
      for i in range(len(X)):
          X_out.append(X.iloc[i:(i+1)].values)
          y_out.append(y.iloc[i])
      return np.array(X_out), np.array(y_out)


  X_test, y_test = create_sequences(test[['Frequency']], test['Frequency'])
  X_test_pred = model1.predict(X_test, verbose=1)
  test_mae_loss = np.mean(np.abs(X_test_pred-X_test), axis=1)
  threshold = np.max(test_mae_loss)
  # Find anomalies
  anomaly_df = pd.DataFrame(test[0:])
  anomaly_df['loss'] = test_mae_loss
  anomaly_df['threshold'] = threshold
  anomaly_df['anomaly'] = anomaly_df['loss'] >= anomaly_df['threshold']

  anomalies = list(anomaly_df['anomaly'].values)
  ret = []
  for i in anomalies:
    ret.append(str(i))
  return ret
for i in data_country:
  data_country[i]["Mention_Anomalies"] = return_anomalies(data_country[i]["Mentions"])
  data_country[i]["Score_Anomalies"] = return_anomalies(data_country[i]["Score"])
  data_country[i]["Host_Anomalies"] = return_anomalies(data_country[i]["Host"])
  data_country[i]["URL_Anomalies"] = return_anomalies(data_country[i]["URL"])
  data_country[i]["Address_Anomalies"] = return_anomalies(data_country[i]["Address"])
  data_country[i]["File_Anomalies"] = return_anomalies(data_country[i]["File"])
  data_country[i]["CIDR_Anomalies"] = return_anomalies(data_country[i]["CIDR"])
  data_country[i]["ASN_Anomalies"] = return_anomalies(data_country[i]["ASN"])
  data_country[i]["Email_Anomalies"] = return_anomalies(data_country[i]["Email"])
for i in data_owner:
  data_owner[i]["Mention_Anomalies"] = return_anomalies(data_owner[i]["Mentions"])
  data_owner[i]["Score_Anomalies"] = return_anomalies(data_owner[i]["Score"])
  data_owner[i]["Host_Anomalies"] = return_anomalies(data_owner[i]["Host"])
  data_owner[i]["URL_Anomalies"] = return_anomalies(data_owner[i]["URL"])
  data_owner[i]["Address_Anomalies"] = return_anomalies(data_owner[i]["Address"])
  data_owner[i]["File_Anomalies"] = return_anomalies(data_owner[i]["File"])
  data_owner[i]["CIDR_Anomalies"] = return_anomalies(data_owner[i]["CIDR"])
  data_owner[i]["ASN_Anomalies"] = return_anomalies(data_owner[i]["ASN"])
  data_owner[i]["Email_Anomalies"] = return_anomalies(data_owner[i]["Email"])
with open("Country_ML.json", "w") as outfile3: 
    json.dump(data_country, outfile3)
with open("Owner_ML.json", "w") as outfile4: 
    json.dump(data_owner, outfile4)

f100 = open('Owner_ML.json',)
f00 = open('Country_ML.json',)
data_country = json.load(f00)
data_owner = json.load(f100)
for i in data_owner:
  data_country[i] = data_owner[i]
fulldata = {"Country":[],"Mention":[],"Mention_Anomalies":[],"Rating":[],"Rating_Anomalies":[],"IP":[],"IP_Anomalies":[],"Host":[],"Host_Anomalies":[],"Email":[],"Email_Anomalies":[],"File":[],"File_Anomalies":[],"Date":[]}
fulldata = pd.DataFrame(data=fulldata)
countrywtf = []
for i in data_country:
  for l in range(len(data_country[i]["Date"])):
    countrywtf.append(i)
  a = data_country[i]["Mentions"]
  aa = data_country[i]["Mention_Anomalies"]
  b = data_country[i]["Score"]
  bb = data_country[i]["Score_Anomalies"]
  c = data_country[i]["Host"]
  cc = data_country[i]["Host_Anomalies"]
  d = data_country[i]["Address"]
  dd = data_country[i]["Address_Anomalies"]
  e = data_country[i]["File"]
  ee = data_country[i]["File_Anomalies"]
  f = data_country[i]["Email"]
  ff = data_country[i]["Email_Anomalies"]
  g = data_country[i]["Date"]
  #print(a,b,c,d,e,f,g)
  for ii in range(len(aa)):
    if aa[ii] == "True":
      aa[ii] = a[ii]
    else:
      aa[ii] = 0

    if bb[ii] == "True":
      bb[ii] = b[ii]
    else:
      bb[ii] = 0

    if cc[ii] == "True":
      cc[ii] = c[ii]
    else:
      cc[ii] = 0
    
    if dd[ii] == "True":
      dd[ii] = d[ii]
    else:
      dd[ii] = 0
    
    if ee[ii] == "True":
      ee[ii] = e[ii]
    else:
      ee[ii] = 0

    if ff[ii] == "True":
      ff[ii] = f[ii]
    else:
      ff[ii] = 0
  for k in range(len(a)):
    fulldata = fulldata.append({"Country":countrywtf[k],"Mention":a[k],"Mention_Anomalies":aa[k],"Rating":b[k],"Rating_Anomalies":bb[k],"IP":d[k],"IP_Anomalies":dd[k],"Host":c[k],"Host_Anomalies":cc[k],"Email":f[k],"Email_Anomalies":ff[k],"File":e[k],"File_Anomalies":ee[k],"Date":g[k]},ignore_index=True)
  countrywtf = []
fulldata.to_csv("final.csv",index=False)
print("Exit without issue")

