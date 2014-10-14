insecure-wp-admin-password-check
================================

Finds Wordpress Admin account with commonly used insecure passwords

<h2>Requires:</h2>
https://github.com/exavolt/python-phpass

<h2>Example Run:</h2>
```
[root@box ~]# python find_bad_wp_passwords.py 
[*] Gathering Wordpress Databases
[*] Gathering Wordpress Admin Users
[*] Running Password Comparisons Between Insecure Password List

*******************************Insecure Passwords Found*****************************
[!] Insecure password found for admin user a:test12345 on http://domain.com/a/

************************************Errors Found************************************
[!] All admin users require conversion from MD5 on http://domain.com/bb/
[!] All admin users require conversion from MD5 on http://domain/~isaac/
[!] All admin users require conversion from MD5 on http://domain.com/c/
[!] All admin users require conversion from MD5 on http://domain.com/d/
[!] All admin users require conversion from MD5 on http://domain.com
[!] All admin users require conversion from MD5 on http://domain.com/e
```

passwords.txt has the top 500 insecure common passwords used.

<h2>Todo:</h2>
Do MD5 conversion for older Wordpress installations


