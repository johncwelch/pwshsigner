##signing script
##we need to store some info, for powershell, like the password for the cert, etc.
##this requires using the security command line for setting and retrieving

##syntax to set generic password: security add-generic-password -a <username of user running script via whoami> -s "pwshsigner" -w "<thepassword>" 