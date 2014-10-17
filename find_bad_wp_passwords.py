#!/usr/bin/python
'''
Author: Matthew Harris <admin@mattharris.org>
Description: Provide interface to test security of Wordpress Admin Passwords and notify of weak passwords
Version: 1.0
Revision: 1
'''
import os
import re
import sys
import phpass
import MySQLdb

'''
Find a list of wordpress databases based of the wp_ table prefix
Currently set to search default value of cPanel boxes
'''
def find_wp_dbs():
    root_dir = '/var/lib/mysql'
    pattern = re.compile("^wp_")
    db_list = []
    print "[*] Gathering Wordpress Databases"
    if os.path.isdir(root_dir):
        for dir_name, sub_dir, file_list in os.walk(root_dir):
            for fname in file_list:
                if pattern.match(fname):
                    db_list.append(os.path.basename(dir_name))
                    break
        password = get_root_db_pass()
        print "[*] Gathering Wordpress Admin Users"
        print "[*] Running Password Comparisons Between Insecure Password List"
        all_errors = []
        all_insecure = []
        password_list = load_password_list()
        for db in db_list:
            data = get_admin_user(db, password)
            (errors, insecure) = test_passwords(data, password_list)
            if errors:
                all_errors.append(errors)
            if insecure:
                all_insecure.append(insecure)
        display_output(all_errors, all_insecure)
    else:
        print 'MySQL directory does not exist.' + "\n"

'''
Requires root to save on io operations on reading possibly thousands of
wp-config.php files to parse db data
'''
def get_root_db_pass():
    with open('/root/.my.cnf') as f:
        lines = f.readlines()
    pattern = re.compile("^password=(.*)$")
    for line in lines:
        if pattern.match(line):
            match = pattern.match(line)
            return match.group(1)

'''
Function returns a data structure dict of list
'url' => [users]
'''
def get_admin_user(db, password):
    try:
        con = MySQLdb.connect('localhost', 'root', password, db)
        cur = con.cursor()
        cur.execute("""
            SELECT user_login,user_pass FROM wp_users 
            LEFT JOIN wp_usermeta ON wp_users.ID = wp_usermeta.user_id WHERE
            meta_key LIKE '%capabilities%' AND 
            meta_value LIKE '%admin%' 
            ORDER BY umeta_id
        """)
        users = cur.fetchall()
        cur.execute("""
            SELECT option_value FROM wp_options 
            WHERE option_name = 'siteurl';
        """)
        url = cur.fetchone()
        return {'url':url, 'users':users}
    except MySQLdb.Error, e:
        print "Error %d: %s" % (e.args[0], e.args[1])
    finally:
        if con:
            con.close()

'''
Load a precompiled list of commonly used insecure passwords
'''
def load_password_list():
    with open('passwords.txt') as f:
        passwords = f.readlines()
    return passwords

'''
Test the site admin against common easily crackable passwords
'''
def test_passwords(data, password_list):
    url = data['url'][0]
    users = data['users']
    user_count = len(users)
    total_md5 = 0
    errors = []
    insecure = []
    for username, password_hash in users:
        if len(password_hash) <= 32:
            '''
            Haven't written support yet for older versions and md5 conversion
            '''
            total_md5 += 1
        else:
            wp_hasher = phpass.PasswordHash(8, True)
            for p in password_list:
                p = p.strip()
                if wp_hasher.check_password(p, password_hash):
                    insecure.append("[!] Insecure password found for admin user %s:%s on %s" % (username, p, url))

    if total_md5 == user_count:
        errors.append("[!] All admin users require conversion from MD5 on %s" % url)

    return errors, insecure

'''
Display errors and insecure passwords
'''
def display_output(errors, insecure):
    print
    print "*******************************Insecure Passwords Found*****************************"
    for i in insecure:
        print "\n".join(i)
    print
    print "************************************Errors Found************************************"
    for e in errors:
        print "\n".join(e)

if __name__ == "__main__":
    find_wp_dbs()
