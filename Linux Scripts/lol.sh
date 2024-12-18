#!/bin/bash

number=0
cut -d: -f1 /etc/passwd
read -p "Enter the number of users to be deleted: " num_delusers

if [ "$num_delusers" -gt 1 ]; then
    for ((i=1; i<=$num_delusers; i++)); do
        read -p "Enter username to be deleted ($i) : " del_userlist[$i]
    done
else
    read -p "Enter Username to be deleted: " del_userlist[1]
    num_delusers=1
fi

if [ "$num_delusers" -gt 1 ]; then
    for ((i=1; i<=$num_delusers; i++)); do
        echo "User to be deleted $i = ${del_userlist[$i]}"
    done
else
    echo "User to be deleted = ${del_userlist[1]}"
fi

while [ "$number" -lt "$num_delusers" ]; do
    ((number+=1))
    username="${del_userlist[$number]}"
    if id "$username" &>/dev/null; then
        userdel -r "$username"
        echo "User '$username' deleted successfully."
    else
        echo "User '$username' does not exist or is already deleted."
    fi
done