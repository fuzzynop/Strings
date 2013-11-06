#! /usr/bin/python

import os
import md5
import sys
import subprocess
import datetime
import pefile
import peutils


#******************
#**  INIT *********
#******************
#parse args
#TODO - do this right 

#get filename from argument
filename = sys.argv[1]

##GET MD5 Hash of malware
try:
  mal_file = open(sys.argv[1],'rb')
  mal_file_data = mal_file.read()
  MD5 = md5.md5(mal_file_data).hexdigest().upper()
  mal_file.close()
except:
  print sys.argv[1],'not found.'
  sys.exit() 



#---------------------
#GET Strings from file
#---------------------

#frisbie's regexes

#input = subprocess.check_output(['strings','-n','8','-a',filename])
#ips = re.findall( r'[0-9]+(?:\.[0-9]{1,3}){3}', input)
#ips = list(set(ips))
#domains = re.findall( r'([_a-zA-Z0-9.\-]+\.[_a-zA-Z]{2,4})', input)
#domains = list(set(domains))

STRINGS = subprocess.check_output(['strings','-n','8','-a',filename]).split('\n')

NEAT_STRINGS = []
NEAT_WORDS = ['www','http','.exe','.rar','.ini','.dll','.txt',
'C:\\','LoadLibrary','Create','write','User-Agent',
'ControlSet','CurrentVersion','.sys','.dat','.pdb','.com','Active Setup','.mdt',
'service','mozilla','socket','admin','Microsoft','Hook','EventLog','GetKeyState']
OTHER_STRINGS = []

for STRING in STRINGS:
  for WORD in NEAT_WORDS:
    if WORD.lower() in STRING.lower():
      NEAT_STRINGS.append(STRING)


#---------------------
#GET entropy
#---------------------
try:
  pe = pefile.PE(filename)
  ENTROPY =  "SECTIONS     ENTROPY:"
  for section in pe.sections:
      ENTROPY = ENTROPY + "\n    %-12s %.2f" % (section.Name.rstrip('\0') + ":", section.get_entropy())

  #-----------------------
  #GET compile timestamp
  #-----------------------
  COMPILE_TIME = "\nCOMPILE_TIME:\n    "+pe.FILE_HEADER.dump()[3][60:-1]

  
except:
  ENTROPY = "SECTIONS      ENTROPY:\n    *FAILED*"
  COMPILE_TIME = "\nCOMPILE_TIME:\n    *FAILED*"


#---------------------------
#GET result of file command
#---------------------------
FILE_INFO = subprocess.check_output(['file',filename]).split(';')[1]


#check DLL stuff
DLL_EXPORTS = ''
DLL_IMPORTS = ''
try:
  pe = pefile.PE(filename)
  if pe.FILE_HEADER.IMAGE_FILE_DLL == True:
      if len(pe.DIRECTORY_ENTRY_EXPORT.symbols) > 0:
          DLL_EXPORTS =  "\n\nDLL_EXPORTS:"
          for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
              DLL_EXPORTS += "\n    " + export.name
        
      addr_name = pe.DIRECTORY_ENTRY_EXPORT.struct.Name
      name = pe.get_memory_mapped_image()[addr_name:addr_name+256].split('\0', 1)[0]
      DLL_EXPORTS += "\n\nThe DLL exports its original name as " + name
except:
  DLL_EXPORTS = "\n\nDLL_EXPORTS:\n    ERROR"
  
# try:
  # DLL_IMPORTS = "\n\nDLL_IMPORTS:"      
  # for entry in pe.DIRECTORY_ENTRY_IMPORT:
    # DLL_IMPORTS += '\n\n    ' + entry.dll 
    # for imp in entry.imports:
      # DLL_IMPORTS += '\n      ' + imp.name      
# except:
  # DLL_IMPORTS = "\n\nDLL_IMPORTS:\n    ERROR"

#*******************************
#** WRITE **********************
#*******************************
OUT = ''



#Filename
OUT += '\n\nFILE: \n    '
OUT += filename

#MD5
OUT += '\n\nMD5: \n    '
OUT += MD5


#FILE_INFO
OUT += '\n\nFILE_INFO: \n   '
OUT += FILE_INFO


#Compile Date
OUT += COMPILE_TIME

#ENTROPY
OUT += '\n\n'
OUT += ENTROPY


#DLL_EXPORTS
OUT += DLL_EXPORTS

#DLL_IMPORTS

OUT += DLL_IMPORTS

#Strings
OUT += '\n\nSTRINGS:\n'
for NEAT in NEAT_STRINGS:
  OUT += '    '
  OUT += NEAT
  OUT += '\n'
OUT += '\n    --------------------------------------\n\n'
for STRING in STRINGS:
  if STRING not in NEAT_STRINGS:
    OUT += '    '
    OUT += STRING
    OUT += '\n'
print OUT






imports_i_care_about = ['RegSetValue','GetWindowText','SetWindowsHook','CallNextHook','WriteFile',]

