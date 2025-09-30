# encrypted-photo-backup-to-wasabi-with-powershell
Encrypt and back up photos to Wasabi using PowerShell

# Config and execution
* Create a cronjob to run backup.ps1 however often you'd like to back up files in the photo directory
* As you accumulate photos, dump them into your photo directory
* The script will run at the specified frequency to encrypt and upload the files to a Wasabi bucket
* The script maintains a sqlite database of file hashes to keep track of which photo files it has uploaded already

# todos
* Add finally block to clean up in case of script interruption
* Add logic to query photos and download / decrypt them
* Add logic to integrate with an LLM that could review a photo's thumbnail and provide a file name suggestion based on photo content
