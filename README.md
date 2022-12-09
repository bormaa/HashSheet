# Hash Sheet
        _   _           _       ____  _               _   
        | | | | __ _ ___| |__   / ___|| |__   ___  ___| |_ 
        | |_| |/ _` / __| '_ \  \___ \| '_ \ / _ \/ _ \ __|
        |  _  | (_| \__ \ | | |  ___) | | | |  __/  __/ |_ 
        |_| |_|\__,_|___/_| |_| |____/|_| |_|\___|\___|\__|

HashSheet is a tool that helps you to get different hashes from one hash using VirusTotal API. The tool can be easily used and it will scan CSV files for any hash and find equivalent MD5, SHA-1, and SHA-256 hashes and save the output to CSV file Tool is not too fast as VirusTotal sets a limit of 4 requests per minute this is why it is recommended to use multiple keys.
# installation
The `requirements.txt` file should list all Python libraries that program depend on, and they will be installed using:

```
pip install -r requirements.txt
```
# Usage
```
usage: hashsheet.py [-h] [-w WAIT] [-p] [-o OUTPUT] [-t THREAD] keys_file hashes_file

HashSheet is a simple program to get equivelent hashes of same file from VirusTotal into one sheet without duplicates

positional arguments:
  keys_file             txt file that includes the VirusTotal keys
  hashes_file           csv file that includes the hashes

options:
  -h, --help            show this help message and exit
  -w WAIT, --wait WAIT  Specify the wait time between requests, free VirusTotal allow only 4 requests per minutes
  -p, --premium         This option to indicate that your virustotal is premium to set wait time to 0
  -o OUTPUT, --output OUTPUT
                        Specify the output name of sheet
  -t THREAD, --thread THREAD
                        Specify the maximum number of threads

```
# Example
```
python3 hashsheet.py keys.txt hashes.csv
```
The `keys.txt` file can include as many keys as you want.\
The option `-t` can help when you have premium or many keys

# Credits

This code was developed by Ebraam Mesak @bormaa
