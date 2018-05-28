
# Virus Anlyzer
virus/malware analyzer using signature patterns of each infection using yara. 

[![N|Solid](https://javacc.org/new-javacc-logo.png)](https://javacc.org/)
# Instructions to use and upgrade
1. download yara executable from https://code.google.com/archive/p/yara-project/downloads
2. extract archive to the working derectory where analyse.cmd located.
3. move suspected files to infected folder.
4. to analyze files run : 

if shell:
```sh
./analyze
```

if cmd:
```sh
analyze
```
5. to upgrade analyzer, add new rule files to rules/ and include the newfile inside the index.yar as :
```sh
include "newfile.yar"
```
